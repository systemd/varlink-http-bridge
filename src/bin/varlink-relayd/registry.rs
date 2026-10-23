// SPDX-License-Identifier: LGPL-2.1-or-later

//! The connected nodes, the only state the node and caller side share.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;

use bytes::Bytes;
use h2::client::SendRequest;

use varlink_http_bridge::node_id::NodeId;

#[derive(Default)]
pub(crate) struct Nodes {
    // None until the node answered its first PING, so that callers are
    // never routed to a peer that only completed the upgrade
    map: Mutex<HashMap<NodeId, Option<SendRequest<Bytes>>>>,
}

/// A node id held in [`Nodes`], released again on drop.
pub(crate) struct Reservation<'a> {
    nodes: &'a Nodes,
    pub(crate) id: NodeId,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        // no owner check needed, first-wins means there is no other
        // reservation for this id
        self.nodes.map.lock().expect("nodes lock").remove(&self.id);
    }
}

impl Nodes {
    /// Reserve `id`, first-wins: `None` while another connection holds it.
    pub(crate) fn reserve(&self, id: NodeId) -> Option<Reservation<'_>> {
        match self.map.lock().expect("nodes lock").entry(id) {
            Entry::Occupied(_) => None,
            Entry::Vacant(entry) => {
                entry.insert(None);
                Some(Reservation { nodes: self, id })
            }
        }
    }

    pub(crate) fn attach(&self, reservation: &Reservation<'_>, h2: SendRequest<Bytes>) {
        self.map
            .lock()
            .expect("nodes lock")
            .insert(reservation.id, Some(h2));
    }

    pub(crate) fn get(&self, id: NodeId) -> Option<SendRequest<Bytes>> {
        self.map.lock().expect("nodes lock").get(&id)?.clone()
    }

    #[cfg(test)]
    pub(crate) fn occupied(&self, id: NodeId) -> bool {
        self.map.lock().expect("nodes lock").contains_key(&id)
    }
}
