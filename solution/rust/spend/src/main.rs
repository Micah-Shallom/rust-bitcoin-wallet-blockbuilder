extern crate balance;
use balance::{recover_wallet_state, EXTENDED_PRIVATE_KEY, bcli};
use hex_literal::hex;
use spend::{spend_p2wpkh, spend_p2wsh, test_get_hash_commitment};
use serde_json::Value;

fn main() {
    // Default Bitcoin Core cookie path
    let cookie_filepath = "~/.bitcoin/signet/.cookie";

    // Uncomment to test the hash commitment function
    // test_get_hash_commitment();

    // Recover the wallet state
    let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY, cookie_filepath).unwrap();
    // println!("Wallet state recovered successfully.");

    // Spend from P2WPKH and create a P2WSH multisig output
    let (txid1, tx1) = spend_p2wpkh(&wallet_state).unwrap();
    // println!("First transactio (P2WPKH -> P2WSH) created successfully.");
    // println!("Transaction 1 ID: {}", hex::encode(&txid1));
    println!("{}", tx1);


    // Define the multisig output details

    // Spend from the P2WSH multisig output
    match spend_p2wsh(&wallet_state, txid1) {
        Ok(transaction_data) => {
            let txid2 = hex::encode(&transaction_data[0]); // TXID of the second transaction
            let tx2 = hex::encode(&transaction_data[1]); // Serialized transaction

            // println!("Second transaction (P2WSH -> OP_RETURN + Change) created successfully.");
            // println!("Transaction 2 ID: {}", txid2);
            println!("{}", tx2);

            // // Decode the first transaction
            // let command = format!("decoderawtransaction {}", tx1);
            // let result = bcli(&command).unwrap();
            // println!("\nDecoded Transaction 1:\n{}", String::from_utf8(result).unwrap());

            // // Decode the second transaction
            // let command = format!("decoderawtransaction {}", tx2);
            // let result = bcli(&command).unwrap();
            // println!("\nDecoded Transaction 2:\n{}", String::from_utf8(result).unwrap());

            // // Test mempool acceptance for both transactions
            // let command = format!(
            //     "testmempoolaccept {}",
            //     serde_json::to_string(&[tx1, tx2]).unwrap()
            // );
            // let result = bcli(&command).unwrap();
            // println!("\nTest Mempool Accept Result:\n{}", String::from_utf8(result).unwrap());
        }
        Err(e) => {
            // println!("Failed to create the second transaction: {:?}", e);
        }
    }
}