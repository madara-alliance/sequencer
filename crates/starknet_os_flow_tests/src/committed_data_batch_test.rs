//! Standard preimages and original request ordering, including duplicate absent reads.
use blockifier::execution::syscalls::committed_data::{CommittedDataBatchProof, CommittedDataSet};
use starknet_types_core::felt::Felt;
#[test]
fn standard_batch_merges_membership_and_absence_preimages() {
    let tree =
        CommittedDataSet::new(vec![(Felt::TWO, Felt::from(100)), (Felt::THREE, Felt::from(125))])
            .unwrap();
    let keys = [Felt::TWO, Felt::ZERO, Felt::THREE, Felt::TWO, Felt::ZERO];
    let proof = CommittedDataBatchProof::from_dataset(&tree, &keys).unwrap();
    assert_eq!(proof.unique_leaves(), 3);
    let values: Vec<_> = proof.indices.iter().map(|i| proof.leaves[2 * i + 1]).collect();
    assert_eq!(
        values,
        vec![Felt::from(100), Felt::ZERO, Felt::from(125), Felt::from(100), Felt::ZERO]
    );
    for key in keys {
        for (hash, preimage) in tree.lookup_witness(key).facts().unwrap() {
            assert_eq!(proof.facts[&hash], preimage);
        }
    }
    assert!(
        CommittedDataBatchProof::new(tree.root(), &keys, |key| {
            let mut proof = tree.lookup_witness(key);
            proof.value += Felt::ONE;
            Ok(Some(proof))
        })
        .is_err()
    );
}
