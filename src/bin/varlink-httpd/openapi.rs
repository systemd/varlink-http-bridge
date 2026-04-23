// SPDX-License-Identifier: LGPL-2.1-or-later

use serde_json::{Value, json};
use zlink::idl::{CustomType, Field, Interface, Type};

fn type_to_schema(ty: &Type) -> Value {
    match ty {
        Type::Bool => json!({"type": "boolean"}),
        Type::Int => json!({"type": "integer", "format": "int64"}),
        Type::Float => json!({"type": "number"}),
        Type::String => json!({"type": "string"}),
        Type::ForeignObject | Type::Any => json!({"type": "object"}),
        Type::Custom(name) => {
            json!({"$ref": format!("#/components/schemas/{name}")})
        }
        Type::Optional(inner) => type_to_schema(inner.inner()),
        Type::Array(inner) => {
            json!({"type": "array", "items": type_to_schema(inner.inner())})
        }
        Type::Map(inner) => {
            json!({"type": "object", "additionalProperties": type_to_schema(inner.inner())})
        }
        Type::Object(fields) => fields_to_schema(fields.iter()),
        Type::Enum(variants) => {
            let names: Vec<&str> = variants.iter().map(|v| v.name()).collect();
            json!({"type": "string", "enum": names})
        }
    }
}

fn fields_to_schema<'a>(fields: impl Iterator<Item = &'a Field<'a>>) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for field in fields {
        let mut schema = type_to_schema(field.ty());
        if let Some(desc) = comments_to_string(field.comments()) {
            if let Value::Object(ref mut map) = schema {
                map.insert("description".to_string(), json!(desc));
            }
        }
        properties.insert(field.name().to_string(), schema);
        if !matches!(field.ty(), Type::Optional(_)) {
            required.push(json!(field.name()));
        }
    }

    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), Value::Array(required));
    }
    Value::Object(schema)
}

fn comments_to_string<'a>(
    comments: impl Iterator<Item = &'a zlink::idl::Comment<'a>>,
) -> Option<String> {
    let parts: Vec<&str> = comments.map(|c| c.content()).collect();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// How a method relates to varlink's `more` flag, derived from the
/// systemd IDL comment convention.
enum MoreFlag {
    /// No `more` support — single JSON response only.
    None,
    /// `[Supports 'more' flag]` — client may optionally use `more: true`.
    Supports,
    /// `[Requires 'more' flag]` — client must use `more: true`.
    Requires,
}

fn method_more_flag(method: &zlink::idl::Method) -> MoreFlag {
    for c in method.comments() {
        let s = c.content();
        if s.contains("[Requires 'more' flag]") {
            return MoreFlag::Requires;
        }
        if s.contains("[Supports 'more' flag]") {
            return MoreFlag::Supports;
        }
    }
    MoreFlag::None
}

pub fn idl_to_openapi(address: &str, iface: &Interface) -> Value {
    let mut paths = serde_json::Map::new();

    for method in iface.methods() {
        let full_method = format!("{}.{}", iface.name(), method.name());
        let path = format!("/call/{address}/{full_method}");

        let mut operation = serde_json::Map::new();
        operation.insert("operationId".to_string(), json!(method.name()));
        if let Some(desc) = comments_to_string(method.comments()) {
            operation.insert("description".to_string(), json!(desc));
        }
        operation.insert(
            "requestBody".to_string(),
            json!({
                "required": true,
                "content": {
                    "application/json": {
                        "schema": fields_to_schema(method.inputs())
                    }
                }
            }),
        );
        let output_schema = fields_to_schema(method.outputs());
        let more_flag = method_more_flag(&method);

        let json_seq_entry = json!({
            "description": "Streaming response using the varlink 'more' flag. Each reply is encoded as an RFC 7464 JSON text sequence (RS 0x1E + JSON + LF). Request this format via Accept: application/json-seq.",
            "schema": output_schema
        });

        let mut content = serde_json::Map::new();
        match more_flag {
            MoreFlag::None => {
                content.insert(
                    "application/json".to_string(),
                    json!({"schema": output_schema}),
                );
            }
            MoreFlag::Supports => {
                content.insert(
                    "application/json".to_string(),
                    json!({"schema": output_schema}),
                );
                content.insert("application/json-seq".to_string(), json_seq_entry);
            }
            MoreFlag::Requires => {
                content.insert("application/json-seq".to_string(), json_seq_entry);
            }
        }

        operation.insert(
            "responses".to_string(),
            json!({
                "200": {
                    "description": "Successful response",
                    "content": Value::Object(content)
                }
            }),
        );

        let path_item = json!({ "post": Value::Object(operation) });
        paths.insert(path, path_item);
    }

    let mut schemas = serde_json::Map::new();

    for custom_type in iface.custom_types() {
        let (mut schema, desc) = match custom_type {
            CustomType::Object(obj) => (
                fields_to_schema(obj.fields()),
                comments_to_string(obj.comments()),
            ),
            CustomType::Enum(e) => {
                let names: Vec<&str> = e.variants().map(|v| v.name()).collect();
                (
                    json!({"type": "string", "enum": names}),
                    comments_to_string(e.comments()),
                )
            }
        };
        if let Some(desc) = desc {
            if let Value::Object(ref mut map) = schema {
                map.insert("description".to_string(), json!(desc));
            }
        }
        schemas.insert(custom_type.name().to_string(), schema);
    }

    for error in iface.errors() {
        let mut schema = fields_to_schema(error.fields());
        if let Some(desc) = comments_to_string(error.comments()) {
            if let Value::Object(ref mut map) = schema {
                map.insert("description".to_string(), json!(desc));
            }
        }
        schemas.insert(error.name().to_string(), schema);
    }

    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {
            "title": iface.name(),
            "version": "0.0.0",
        },
        "paths": paths,
    });

    if let Some(desc) = comments_to_string(iface.comments()) {
        if let Value::Object(ref mut info_obj) = doc["info"] {
            info_obj.insert("description".to_string(), json!(desc));
        }
    }

    if !schemas.is_empty() {
        if let Value::Object(ref mut doc_obj) = doc {
            doc_obj.insert("components".to_string(), json!({ "schemas": schemas }));
        }
    }

    doc
}
