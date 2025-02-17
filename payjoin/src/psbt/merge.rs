//! Utilities for merging unique v0 PSBTs
use bitcoin::Psbt;

/// Try to merge two PSBTs
/// PSBTs here should not have the same unsigned tx
/// if you do have the same unsigned tx, use `combine` instead
/// Note: this method does not merge non inputs or outputs
/// Note: if there are duplicate inputs, the first input will be kept
/// Note: if there are duplicate outputs, both outputs will be kept
pub(crate) fn merge_unsigned_tx(acc: Psbt, psbt: Psbt) -> Psbt {
    let mut unsigned_tx = acc.unsigned_tx;
    unsigned_tx.input.extend(psbt.unsigned_tx.input);
    unsigned_tx.input.dedup_by_key(|input| input.previous_output);
    unsigned_tx.output.extend(psbt.unsigned_tx.output);

    let mut merged_psbt =
        Psbt::from_unsigned_tx(unsigned_tx).expect("pulling from unsigned tx above");
    let zip = acc.inputs.iter().chain(psbt.inputs.iter()).collect::<Vec<_>>();
    merged_psbt.inputs.iter_mut().enumerate().for_each(|(i, input)| {
        input.witness_utxo = zip[i].witness_utxo.clone();
    });
    merged_psbt
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::key::rand::Rng;
    use bitcoin::secp256k1::rand::thread_rng;
    use bitcoin::secp256k1::SECP256K1;
    use bitcoin::{
        Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness,
    };

    use super::merge_unsigned_tx;

    /// Create a random p2wpkh script
    fn random_p2wpkh_script() -> ScriptBuf {
        let sk = bitcoin::PrivateKey::generate(Network::Bitcoin);
        let pk = sk.public_key(SECP256K1);

        pk.p2wpkh_script_code().unwrap()
    }

    /// Create a random 32 byte txid
    fn random_txid() -> Txid {
        let mut rng = thread_rng();
        let mut txid = [0u8; 32];
        rng.try_fill(&mut txid).expect("should fill");
        Txid::from_slice(&txid).unwrap()
    }

    /// Create a tx with random inputs and outputs
    /// Note: all outputs have the same 1000 sat value
    /// Transactions are created with version 2
    fn create_tx(num_inputs: usize, num_outputs: usize) -> Transaction {
        let txid = random_txid();

        let mut inputs = vec![];
        for i in 0..num_inputs {
            let op = OutPoint::new(txid, i as u32);
            inputs.push(TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Default::default(),
            });
        }

        let mut outputs = vec![];
        for _ in 0..num_outputs {
            outputs.push(TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: random_p2wpkh_script(),
            });
        }

        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        }
    }

    /// Test that we can merge two psbts with unique unsigned txs
    #[test]
    fn test_merge_unsigned_txs() {
        let txs = (0..10).map(|_| create_tx(2, 3)).collect::<Vec<_>>();
        let psbts = txs.iter().map(|tx| Psbt::from_unsigned_tx(tx.clone()).unwrap());
        let merged_psbt = psbts.reduce(merge_unsigned_tx).unwrap();

        for tx in txs.iter() {
            assert!(merged_psbt.unsigned_tx.input.contains(&tx.input[0]));
            assert!(merged_psbt.unsigned_tx.input.contains(&tx.input[1]));
            assert!(merged_psbt.unsigned_tx.output.contains(&tx.output[0]));
            assert!(merged_psbt.unsigned_tx.output.contains(&tx.output[1]));
            assert!(merged_psbt.unsigned_tx.output.contains(&tx.output[2]));
        }
    }

    /// Test merging empty PSBTs
    #[test]
    fn test_merge_empty_psbts() {
        let tx_1 = create_tx(0, 0);
        let tx_2 = create_tx(0, 0);
        let psbts =
            vec![Psbt::from_unsigned_tx(tx_1).unwrap(), Psbt::from_unsigned_tx(tx_2).unwrap()];

        let merged_psbt = psbts.into_iter().reduce(merge_unsigned_tx).unwrap();

        assert_eq!(merged_psbt.inputs.len(), 0);
        assert_eq!(merged_psbt.outputs.len(), 0);
    }

    /// Test that we cannot merge two psbts if psbts share inputs
    #[test]
    fn should_not_merge_if_psbt_share_inputs() {
        let tx = create_tx(1, 1);
        let psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        let psbts = vec![psbt.clone(), psbt.clone()];

        let res = psbts.into_iter().reduce(merge_unsigned_tx).unwrap();
        let unsigned_tx = res.unsigned_tx;

        assert_eq!(unsigned_tx.input.len(), 1);
        assert_eq!(unsigned_tx.input[0].previous_output, tx.input[0].previous_output);
        assert_eq!(unsigned_tx.output.len(), 2);
        assert_eq!(unsigned_tx.output[0], tx.output[0]);
        assert_eq!(unsigned_tx.output[1], tx.output[0]);
    }

    /// Test that we cannot merge two psbts if psbts have inputs with witness data
    #[test]
    fn should_not_merge_signed_psbt() {
        let tx_1 = create_tx(1, 1);
        let tx_2 = create_tx(1, 1);
        let mut original_psbt = Psbt::from_unsigned_tx(tx_1.clone()).unwrap();
        let mut other = Psbt::from_unsigned_tx(tx_2.clone()).unwrap();

        original_psbt.inputs[0].final_script_witness = Some(Witness::new());
        original_psbt.unsigned_tx.input[0].witness = Witness::new();
        other.inputs[0].final_script_witness = Some(Witness::new());
        let psbts = vec![original_psbt.clone(), other.clone()];
        let merged_psbt = psbts.into_iter().reduce(merge_unsigned_tx).unwrap();

        assert_eq!(merged_psbt.unsigned_tx.input[0], original_psbt.unsigned_tx.input[0]);
        assert_eq!(merged_psbt.unsigned_tx.input[1], other.unsigned_tx.input[0]);
        assert_eq!(merged_psbt.unsigned_tx.output[0], original_psbt.unsigned_tx.output[0]);
        assert_eq!(merged_psbt.unsigned_tx.output[1], other.unsigned_tx.output[0]);
    }

    /// Test merging PSBTs with only inputs or only outputs
    #[test]
    fn test_merge_inputs_or_outputs_only() {
        let tx_1 = create_tx(2, 0);
        let tx_2 = create_tx(0, 3);

        let psbts =
            vec![Psbt::from_unsigned_tx(tx_1).unwrap(), Psbt::from_unsigned_tx(tx_2).unwrap()];

        let merged_psbt = psbts.into_iter().reduce(merge_unsigned_tx).unwrap();

        assert_eq!(merged_psbt.inputs.len(), 2);
        assert_eq!(merged_psbt.outputs.len(), 3);
    }
}
