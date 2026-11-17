# Contributing

## Code review

Rules to enforce when reviewing changes. Each is stated as a concrete,
checkable rule so a reviewer can point at the exact line that breaks it.

- Commit messages explain the "why?" -- the reason/motivation for a change,
  and only briefly the "what"/"how"/"where". Details about the latter belong
  into comments.
- A PR tells a linear story: a later commit never undoes or rewrites what an
  earlier commit in the same PR did. Reviewers read commit-by-commit, so making
  them study code that a later commit throws away wastes their time. Fold the
  fix back into the commit that introduced the problem. Exceptions need a strong
  justification.
- A pure code move (a rename, moving code between files) is its own commit,
  separate from any change in behavior, and says "no behavior change" in its
  message. The move can then be skimmed and the behavior change gets the
  scrutiny.
- The subject of a commit message starts with the area it touches, like
  `httpd:`, `client:` or `auth:`, and `many:` when it spans several. Every
  claim in the message matches the diff.
- `just check` and `just test` pass.
- Data structures are orthogonal, minimal, and non-trivial fields are documented.
- Values that belong together or that have to be valid are their own type
  with a constructor and accessors, not a loose string, a tuple or a nested
  map. A parsed name is a type that can only hold a valid name, so no
  function has to check it again.
- Comments are precise and coincide with what the code does. They explain the
  "why". If the code is not obvious, they also explain the "what?" on
  high-level terms.
- When using/talking to uncommon external APIs, there is a comment with an URL
  pointing to the documentation/specification.
- Any new functionality has a corresponding unit test. They cover the corner
  cases of the code unless they are plausibly "should not happen", like
  `panic!` -- these are often legitimately hard or impossible to reach.
- No `panic` in library code; return an error instead.
- The message of an `expect()`, `assert!` or `unreachable!` says what went
  wrong, like `"config file has more than u32::MAX lines"`. It does not say
  why the author thought it could not happen, like `"checked above"`.

## Comments

- A comment gives the rationale a reader cannot infer from the code, the
  "why". It does not restate what the code does. When in doubt, leave it
  out.
- Comments are short and crisp, without explanatory parentheticals or
  examples.
- A doc comment (`///`, `//!`) says briefly what the item does and how to
  use it: its inputs, what it returns, when to call it. It has no
  implementation details and no rationale. Those go inside the function as
  a regular `//` comment, next to the code they explain.
- The doc comment of a function starts with a verb, like "Returns ..." or
  "Writes ...". A noun phrase is fine for a struct, an enum or a constant.
- Whatever stands directly before an item (fn, impl, const, struct, field)
  is its doc comment and follows the rules above. A plain `//` comment in
  that position is not allowed. For an item without a body, like a const,
  the rationale goes to where the item is used.

## Error handling

We use [anyhow](https://docs.rs/anyhow) for error handling except when
something (like building an HTTP error reply) requires a typed error.

- Errors propagate with `?` and gain a `.context("<what was being
  done>")`. The context is a lowercase explanation like
  `.context("connecting to the varlink socket")`. Use `.with_context(||
  format!(...))` only when the message interpolates, so nothing is
  formatted on the success path.
- Never flatten an error into a string. `map_err(|e| anyhow!("...{e}"))`
  discards the chain and makes the error undowncastable.
- `map_err` is for *converting* into a typed error, either a varlink error
  variant or an error a foreign trait signature requires. It is not a way to
  add context.
- `anyhow!` is for errors that genuinely have no source, e.g. inside
  `Option::ok_or_else`.
- A library crate (below `crates/`) may return anyhow as long as no caller
  needs to tell its failures apart. Once one does, that case gets an error
  type of its own in that crate, and callers match on that type.
