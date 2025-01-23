use crate::parser::Transaction;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};

pub fn write_block_to_file(
    block: Vec<String>,
    transactions: &HashMap<String, Transaction>,
    output_path: &str,
) -> io::Result<()> {
    let mut file = File::create(output_path)?;

    let mut total_weight = 0;
    let mut total_fee = 0;

    for txid in &block {
        if let Some(tx) = transactions.get(txid) {
            total_weight += tx.weight;
            total_fee += tx.fee;
            writeln!(file, "{}", txid)?;
        }
    }

    if total_weight > 4_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Block weight exceeds maximum limit of 4,000,000",
        ));
    }

    println!("Total transactions: {}", block.len());
    println!("Total fee: {}", total_fee);
    println!("Total weight: {}", total_weight);
    println!(
        "Average fee per weight: {:.2}",
        total_fee as f64 / total_weight as f64
    );

    Ok(())
}
