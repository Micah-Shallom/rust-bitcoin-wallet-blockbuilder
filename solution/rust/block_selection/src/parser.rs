// ##############################################
// #              Parser Module                 #
// # This module contains functions and structs #
// # for parsing mempool transactions from a    #
// # CSV file.                                  #
// ##############################################

use csv::ReaderBuilder;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
#[allow(dead_code)]

pub struct Mempool {
    transactions: Vec<Transaction>,
}
#[derive(Debug)]
pub struct Transaction {
    pub txid: String,
    pub fee: u64,
    pub weight: u64,
    pub parents: Vec<String>,
    pub children: Vec<String>,
}

pub fn parse_mempool(file_path: &str) -> Result<HashMap<String, Transaction>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let mut reader = ReaderBuilder::new().has_headers(false).from_reader(file);

    let mut transactions = HashMap::new();

    for result in reader.records() {
        let record = result?;

        if record.len() < 4 {
            continue; //skipping any malformed rows
        }

        let txid = record[0].trim().to_string();
        let fee = record[1].trim().parse::<u64>()?;
        let weight = record[2].trim().parse::<u64>()?;
        let parents: Vec<String> = record[3]
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if weight == 0 {
            return Err("Transaction weight cannot be zero".into());
        }

        transactions.insert(
            txid.clone(),
            Transaction {
                txid,
                fee,
                weight,
                parents,
                children: Vec::new(), //initialize empty
            },
        );
    }

    //build parent-child relationship....for each tx we check all parents if parents already have registered children, then we append this txid into its vector else we create a new vec and add the current txid
    let mut transaction_children = HashMap::new();

    for (txid, transaction) in &transactions {
        for parent in &transaction.parents {
            transaction_children
                .entry(parent.clone())
                .or_insert_with(Vec::new)
                .push(txid.clone());
        }
    }

    //lookup transaactions parent id from the transaction_children hashmap and assign its children to it
    //willbe using it later
    for (parent_txid, children) in &transaction_children {
        if let Some(parent_tx) = transactions.get_mut(parent_txid) {
            parent_tx.children = children.clone();
        }
    }

    Ok(transactions)
}
