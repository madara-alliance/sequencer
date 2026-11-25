//! Standard Starknet Poseidon Patricia commitments: value leaves, binary hashes,
//! and explicit compressed edges. Keys are restricted to 251 bits; zero means absence.
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Poseidon, StarkHash};

use super::CommittedDataError;

/// Same key domain as the OS Patricia implementation.
pub const COMMITTED_DATA_TREE_HEIGHT: usize = 251;
/// Per-import allocation bound, independent of key width and total retained DB size.
pub const MAX_COMMITTED_DATA_VALUES: usize = 524_288;

/// Application-defined key and value. Neither has pricing semantics in the node.
pub type CommittedDataEntry = (Felt, Felt);

/// A bottom-up proof step. Bits must strictly increase, so skipped unary paths cost no nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDataSibling {
    pub bit: u8,
    pub hash: Felt,
}

/// A branch in the compact persistent representation. IDs below the entry count are leaves;
/// other IDs address binary nodes in postorder. Hashes are at bit+1 height;
/// the root or a parent may wrap them in a standard compressed edge.
#[derive(Clone, Copy, Debug)]
pub struct CommittedDataBranch {
    pub bit: u8,
    pub left: u32,
    pub right: u32,
    pub hash: Felt,
}

/// Authenticated lookup evidence for a single (root, key), independent of the reading contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDataWitness {
    /// Exact immutable dataset commitment.
    pub root: Felt,
    /// Requested key; unchanged for both lookup outcomes.
    pub key: Felt,
    /// Authenticated terminal leaf value; not a returned value when `terminal_key` is present.
    pub value: Felt,
    /// Terminal leaf key for an absent lookup. Omitted for membership, preserving its wire form.
    /// Absence is authenticated only when this key differs and follows every requested branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_key: Option<Felt>,
    #[serde(deserialize_with = "deserialize_siblings")]
    pub siblings: Vec<CommittedDataSibling>,
}

fn deserialize_siblings<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<CommittedDataSibling>, D::Error> {
    struct Path;
    impl<'de> serde::de::Visitor<'de> for Path {
        type Value = Vec<CommittedDataSibling>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 251 Patricia branches")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut path = Vec::new();
            while let Some(step) = seq.next_element()? {
                if path.len() == COMMITTED_DATA_TREE_HEIGHT {
                    return Err(serde::de::Error::custom("Patricia path too long"));
                }
                path.push(step);
            }
            Ok(path)
        }
    }
    d.deserialize_seq(Path)
}

/// Standard Patricia leaves contain the value directly.
pub fn leaf(_key: Felt, value: Felt) -> Felt {
    value
}
/// Standard binary node. The level is represented by the path, not a hash domain.
pub fn branch(_bit: u8, left: Felt, right: Felt) -> Felt {
    Poseidon::hash(&left, &right)
}

pub fn valid_key(key: Felt) -> bool {
    key.to_bytes_be()[0] < 8
}

fn edge(hash: Felt, key: Felt, bottom: usize, top: usize) -> (Felt, Option<Vec<Felt>>) {
    if bottom == top || hash == Felt::ZERO {
        return (hash, None);
    }
    let length = top - bottom;
    let mut path = Felt::ZERO;
    for bit in (bottom..top).rev() {
        path = path * Felt::TWO + Felt::from(key_bit(key, bit as u8) as u8);
    }
    (Poseidon::hash(&hash, &path) + Felt::from(length), Some(vec![Felt::from(length), path, hash]))
}

/// Tests a least-significant-bit-numbered position in a canonical felt.
pub fn key_bit(key: Felt, bit: u8) -> bool {
    let bytes = key.to_bytes_be();
    bytes[31 - usize::from(bit) / 8] & (1 << (bit % 8)) != 0
}

impl CommittedDataWitness {
    pub fn read_value(&self) -> Felt {
        if self.terminal_key.is_some() { Felt::ZERO } else { self.value }
    }

    /// Expand the compact transport proof into the standard OS node preimages.
    /// No leaf hash or custom node tag is introduced.
    pub fn facts(&self) -> Option<std::collections::HashMap<Felt, Vec<Felt>>> {
        let terminal = self.terminal_key.unwrap_or(self.key);
        if !valid_key(self.key) || !valid_key(terminal) || self.terminal_key == Some(self.key) {
            return None;
        }
        if self.value == Felt::ZERO {
            return (self.root == Felt::ZERO
                && self.siblings.is_empty()
                && self.terminal_key.is_none())
            .then(std::collections::HashMap::new);
        }
        let mut facts = std::collections::HashMap::new();
        let mut node = self.value;
        let mut height = 0;
        for step in &self.siblings {
            let bit = usize::from(step.bit);
            if bit < height
                || bit >= COMMITTED_DATA_TREE_HEIGHT
                || step.hash == Felt::ZERO
                || key_bit(self.key, step.bit) != key_bit(terminal, step.bit)
            {
                return None;
            }
            let (extended, preimage) = edge(node, terminal, height, bit);
            if let Some(preimage) = preimage {
                facts.insert(extended, preimage);
            }
            let (left, right) = if key_bit(terminal, step.bit) {
                (step.hash, extended)
            } else {
                (extended, step.hash)
            };
            node = branch(step.bit, left, right);
            facts.insert(node, vec![left, right]);
            height = bit + 1;
        }
        let (root, preimage) = edge(node, terminal, height, COMMITTED_DATA_TREE_HEIGHT);
        if let Some(preimage) = preimage {
            facts.insert(root, preimage);
        }
        (root == self.root).then_some(facts)
    }

    pub fn verify(&self) -> bool {
        self.facts().is_some()
    }
}

/// Sorted nonzero entries and compact binary nodes. Edge commitments are derived
/// from child heights and key prefixes, using the standard Starknet encoding.
#[derive(Debug)]
pub struct CommittedDataSet {
    entries: Vec<CommittedDataEntry>,
    branches: Vec<CommittedDataBranch>,
    root: Felt,
}
impl CommittedDataSet {
    /// Sorts keys and rejects duplicates. Input order never changes the root.
    pub fn new(mut entries: Vec<CommittedDataEntry>) -> Result<Self, CommittedDataError> {
        if entries.len() > MAX_COMMITTED_DATA_VALUES {
            return Err(CommittedDataError::InvalidLength);
        }
        if entries.iter().any(|(key, _)| !valid_key(*key)) {
            return Err(CommittedDataError::InvalidWitness);
        }
        entries.sort_unstable_by_key(|entry| entry.0);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(CommittedDataError::DuplicateKey);
        }
        entries.retain(|(_, value)| *value != Felt::ZERO);
        let mut branches = Vec::with_capacity(entries.len().saturating_sub(1));
        let root = if entries.is_empty() {
            Felt::ZERO
        } else {
            let (_, hash) = build(&entries, 0, entries.len() as u32, &mut branches)?;
            let height = branches.last().map_or(0, |node| usize::from(node.bit) + 1);
            edge(hash, entries[0].0, height, COMMITTED_DATA_TREE_HEIGHT).0
        };
        Ok(Self { entries, branches, root })
    }
    /// Copy an immutable snapshot and rehash only branches affected by value changes.
    /// Returns `None` for insertions or zero/deletions, which require rebuilding the topology.
    /// Repeated keys overwrite in slice order; callers still validate import uniqueness.
    pub fn with_updated_values(&self, updates: &[CommittedDataEntry]) -> Option<Self> {
        let mut next = Self {
            entries: self.entries.clone(),
            branches: self.branches.clone(),
            root: self.root,
        };
        let mut changed = vec![false; self.entries.len()];
        for &(key, value) in updates {
            if value == Felt::ZERO {
                return None;
            }
            let index = self.entries.binary_search_by_key(&key, |entry| entry.0).ok()?;
            next.entries[index].1 = value;
            changed[index] = value != self.entries[index].1;
        }
        // Topology is unchanged: visit each branch once, preserving hashes of unchanged subtrees.
        // The arrays are copied so older roots remain usable by concurrent readers.
        fn refresh(
            tree: &mut CommittedDataSet,
            id: usize,
            changed: &[bool],
        ) -> (Felt, Felt, usize, bool) {
            let count = tree.entries.len();
            if id < count {
                let (key, value) = tree.entries[id];
                return (value, key, 0, changed[id]);
            }
            let node = tree.branches[id - count];
            let (left, key, left_height, left_changed) = refresh(tree, node.left as usize, changed);
            let (right, right_key, right_height, right_changed) =
                refresh(tree, node.right as usize, changed);
            let dirty = left_changed || right_changed;
            let hash = if dirty {
                let left = edge(left, key, left_height, usize::from(node.bit)).0;
                let right = edge(right, right_key, right_height, usize::from(node.bit)).0;
                branch(node.bit, left, right)
            } else {
                node.hash
            };
            tree.branches[id - count].hash = hash;
            (hash, key, usize::from(node.bit) + 1, dirty)
        }
        if changed.iter().any(|changed| *changed) {
            let id = next.entries.len() + next.branches.len() - 1;
            let (hash, key, height, _) = refresh(&mut next, id, &changed);
            next.root = edge(hash, key, height, COMMITTED_DATA_TREE_HEIGHT).0;
        }
        Some(next)
    }
    pub fn root(&self) -> Felt {
        self.root
    }
    pub fn entries(&self) -> &[CommittedDataEntry] {
        &self.entries
    }
    pub fn branches(&self) -> &[CommittedDataBranch] {
        &self.branches
    }
    /// Hot execution needs the value and charged path length, without allocating or hashing a
    /// proof.
    pub fn value_and_depth(&self, key: Felt) -> Option<(Felt, usize)> {
        if !valid_key(key) {
            return None;
        }
        if self.entries.is_empty() {
            return Some((Felt::ZERO, 0));
        }
        let count = self.entries.len();
        let mut id = count + self.branches.len() - 1;
        let mut depth = 0;
        while id >= count {
            let node = self.branches[id - count];
            id = if key_bit(key, node.bit) { node.right } else { node.left } as usize;
            depth += 1;
        }
        let (stored_key, value) = self.entries[id];
        (stored_key == key).then_some((value, depth))
    }
    /// Fetch nonzero membership, or a zero proof for an entirely empty tree.
    /// Other missing keys use lookup_witness to authenticate their terminal route.
    pub fn witness(&self, key: Felt) -> Option<CommittedDataWitness> {
        if !valid_key(key) {
            return None;
        }
        let proof = self.lookup_witness(key);
        proof.terminal_key.is_none().then_some(proof)
    }

    /// Follow the requested route even when its leaf is absent. The terminal leaf and siblings
    /// authenticate either membership or non-membership without changing a stored commitment.
    pub fn lookup_witness(&self, key: Felt) -> CommittedDataWitness {
        if self.entries.is_empty() {
            return CommittedDataWitness {
                root: self.root,
                key,
                value: Felt::ZERO,
                terminal_key: None,
                siblings: vec![],
            };
        }
        let count = self.entries.len();
        let mut id = (count + self.branches.len() - 1) as u32;
        let mut siblings = Vec::new();
        while id as usize >= count {
            let node = self.branches[id as usize - count];
            let (child, sibling) = if key_bit(key, node.bit) {
                (node.right, node.left)
            } else {
                (node.left, node.right)
            };
            let hash = if (sibling as usize) < count {
                let entry = self.entries[sibling as usize];
                leaf(entry.0, entry.1)
            } else {
                self.branches[sibling as usize - count].hash
            };
            let sibling_height = if (sibling as usize) < count {
                0
            } else {
                usize::from(self.branches[sibling as usize - count].bit) + 1
            };
            // Recover one descendant key to encode the sibling's compressed edge.
            let mut terminal_id = sibling as usize;
            while terminal_id >= count {
                terminal_id = self.branches[terminal_id - count].left as usize;
            }
            let hash =
                edge(hash, self.entries[terminal_id].0, sibling_height, usize::from(node.bit)).0;
            siblings.push(CommittedDataSibling { bit: node.bit, hash });
            id = child;
        }
        siblings.reverse();
        let (terminal, value) = self.entries[id as usize];
        CommittedDataWitness {
            root: self.root,
            key,
            value,
            siblings,
            terminal_key: (terminal != key).then_some(terminal),
        }
    }
}

fn build(
    entries: &[CommittedDataEntry],
    offset: u32,
    count: u32,
    branches: &mut Vec<CommittedDataBranch>,
) -> Result<(u32, Felt), CommittedDataError> {
    if entries.len() == 1 {
        return Ok((offset, leaf(entries[0].0, entries[0].1)));
    }
    let first = entries[0].0.to_bytes_be();
    let last = entries[entries.len() - 1].0.to_bytes_be();
    // Keys are sorted and unique, so their first differing bit is the subtree's critical bit.
    let bit = first
        .iter()
        .zip(last)
        .enumerate()
        .find_map(|(i, (&a, b))| {
            let xor = a ^ b;
            (xor != 0).then(|| ((31 - i) * 8 + 7 - xor.leading_zeros() as usize) as u8)
        })
        .ok_or(CommittedDataError::DuplicateKey)?;
    let split = entries.partition_point(|entry| !key_bit(entry.0, bit));
    let (left, left_hash) = build(&entries[..split], offset, count, branches)?;
    let (right, right_hash) = build(&entries[split..], offset + split as u32, count, branches)?;
    let child_height =
        |id: u32| if id < count { 0 } else { usize::from(branches[(id - count) as usize].bit) + 1 };
    let left_hash = edge(left_hash, entries[0].0, child_height(left), usize::from(bit)).0;
    let right_hash = edge(right_hash, entries[split].0, child_height(right), usize::from(bit)).0;
    let hash = branch(bit, left_hash, right_hash);
    let id = count + branches.len() as u32;
    branches.push(CommittedDataBranch { bit, left, right, hash });
    Ok((id, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incremental_values_match_rebuild_and_preserve_old_snapshots() {
        let maximum = Felt::TWO.pow(251_u32) - Felt::ONE;
        for keys in [
            vec![],
            vec![Felt::ZERO],
            vec![maximum],
            (0..257_u32).map(Felt::from).collect(),
            (0..251_u32).map(|bit| Felt::TWO.pow(bit)).chain([Felt::ZERO]).collect(),
            (0..129_u32).map(|key| maximum - Felt::from(key * 7919)).collect(),
        ] {
            let mut values: Vec<_> =
                keys.iter().enumerate().map(|(i, key)| (*key, Felt::from(i + 1))).collect();
            let mut tree = CommittedDataSet::new(values.clone()).unwrap();
            for round in 0..4 {
                let original = tree.entries().to_vec();
                let root = tree.root();
                let mut patch = Vec::new();
                for (i, entry) in values.iter_mut().enumerate() {
                    if i % 4 == round {
                        entry.1 = if i % 2 == 0 { Felt::MAX } else { Felt::from(1000 + i + round) };
                        patch.push(*entry);
                    }
                }
                patch.reverse(); // The cache API does not require sorted updates.
                let updated = tree.with_updated_values(&patch).unwrap();
                let rebuilt = CommittedDataSet::new(values.clone()).unwrap();
                assert_eq!(updated.root(), rebuilt.root());
                assert_eq!(updated.entries(), rebuilt.entries());
                for key in [Felt::ZERO, maximum, Felt::from(12345_u32)]
                    .into_iter()
                    .chain(keys.first().copied())
                    .chain(keys.get(keys.len() / 2).copied())
                    .chain(keys.last().copied())
                {
                    assert_eq!(updated.lookup_witness(key), rebuilt.lookup_witness(key));
                    assert!(updated.lookup_witness(key).verify());
                    assert_eq!(updated.value_and_depth(key), rebuilt.value_and_depth(key));
                }
                assert_eq!(tree.root(), root);
                assert_eq!(tree.entries(), original);
                tree = updated;
            }
        }
    }

    #[test]
    fn incremental_values_leave_topology_changes_to_full_rebuild() {
        let tree = CommittedDataSet::new(vec![(Felt::ONE, Felt::TWO)]).unwrap();
        assert!(tree.with_updated_values(&[(Felt::THREE, Felt::ONE)]).is_none());
        assert!(tree.with_updated_values(&[(Felt::ONE, Felt::ZERO)]).is_none());
        assert!(tree.with_updated_values(&[(Felt::TWO.pow(251_u32), Felt::ONE)]).is_none());
        assert_eq!(tree.with_updated_values(&[]).unwrap().root(), tree.root());
        // A later overwrite can cancel an earlier change without invalidating cached hashes.
        assert_eq!(
            tree.with_updated_values(&[(Felt::ONE, Felt::THREE), (Felt::ONE, Felt::TWO)])
                .unwrap()
                .root(),
            tree.root()
        );
    }

    #[test]
    fn standard_patricia_matches_independent_cairo_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../../scripts/committed_data_patricia_vectors.json"
        ))
        .unwrap();
        let mut exported = Vec::new();
        for vector in vectors.as_array().unwrap() {
            let felt =
                |value: &serde_json::Value| Felt::from_dec_str(value.as_str().unwrap()).unwrap();
            let entries = vector["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| (felt(&pair[0]), felt(&pair[1])))
                .collect();
            let tree = CommittedDataSet::new(entries).unwrap();
            assert_eq!(tree.root(), felt(&vector["root"]));
            let keys: Vec<_> = vector["keys"].as_array().unwrap().iter().map(felt).collect();
            let proof = super::super::CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap();
            let facts: Vec<_> = proof
                .facts
                .into_iter()
                .map(|(hash, preimage)| {
                    (hash.to_string(), preimage.iter().map(ToString::to_string).collect::<Vec<_>>())
                })
                .collect();
            exported
                .push(serde_json::json!({"root":tree.root().to_string(), "keys":vector["keys"],
                "entries":vector["entries"], "facts":facts}));
            for key in vector["keys"].as_array().unwrap().iter().map(felt) {
                let proof = tree.lookup_witness(key);
                assert!(proof.verify(), "key {key}");
                let mut bad = proof.clone();
                bad.root += Felt::ONE;
                assert!(!bad.verify());
                let mut bad = proof.clone();
                bad.value += Felt::ONE;
                assert!(!bad.verify());
            }
        }
        if let Some(path) = std::env::var_os("COMMITTED_DATA_PATRICIA_PROOFS") {
            std::fs::write(path, serde_json::to_vec(&exported).unwrap()).unwrap();
        }
    }
    #[test]
    fn zero_is_absence_and_invalid_keys_are_rejected() {
        let tree = CommittedDataSet::new(vec![(Felt::TWO, Felt::from(100))]).unwrap();
        let with_zero =
            CommittedDataSet::new(vec![(Felt::TWO, Felt::from(100)), (Felt::ONE, Felt::ZERO)])
                .unwrap();
        assert_eq!(tree.root(), with_zero.root());
        for query in 0..32 {
            let proof = tree.lookup_witness(Felt::from(query));
            assert!(proof.verify());
            assert_eq!(proof.read_value(), if query == 2 { Felt::from(100) } else { Felt::ZERO });
        }
        assert!(CommittedDataSet::new(vec![(Felt::TWO.pow(251_u32), Felt::ONE)]).is_err());
        assert!(!tree.lookup_witness(Felt::MAX).verify());
        assert!(CommittedDataSet::new(vec![(Felt::ONE, Felt::ONE); 2]).is_err());
        let empty = CommittedDataSet::new(vec![]).unwrap();
        assert_eq!(empty.root(), Felt::ZERO);
        assert!(empty.lookup_witness(Felt::ONE).verify());
    }
    #[test]
    fn paths_are_order_independent_and_tamper_evident() {
        let entries: Vec<_> = (0..251_u32)
            .map(|bit| (Felt::TWO.pow(bit), Felt::from(bit + 1)))
            .chain([(Felt::ZERO, Felt::ONE)])
            .collect();
        let tree = CommittedDataSet::new(entries.clone()).unwrap();
        assert_eq!(
            tree.root(),
            CommittedDataSet::new(entries.into_iter().rev().collect()).unwrap().root()
        );
        let proof = tree.witness(Felt::ZERO).unwrap();
        assert_eq!(proof.siblings.len(), 251);
        assert!(proof.verify());
        let mut bad = proof.clone();
        bad.siblings.swap(0, 1);
        assert!(!bad.verify());
        let mut bad = proof.clone();
        bad.siblings[0].hash += Felt::ONE;
        assert!(!bad.verify());
        let mut bad = proof.clone();
        bad.siblings[0].bit = 251;
        assert!(!bad.verify());
        let mut bad = proof;
        bad.terminal_key = Some(Felt::ZERO);
        assert!(!bad.verify());
    }
}
