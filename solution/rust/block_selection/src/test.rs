use crate::parser::Transaction;
use std::{
    collections::{HashMap, HashSet},
    f64::MAX_10_EXP,
    hash::Hash,
    time::Instant,
};

pub fn evaluate_method(
    method_name: &str,
    method_fn: fn(Vec<String>, &HashMap<String, Transaction>, u64) -> Vec<String>,
    topological_order: Vec<String>,
    transactions: &HashMap<String, Transaction>,
    max_weight: u64,
) -> (String, u64, u64, usize, bool, f64) {
    let start_time = Instant::now();

    let selected_transactions = method_fn(topological_order, transactions, max_weight);

    let elapsed_time = start_time.elapsed().as_secs_f64();

    let mut total_fee = 0;
    let mut total_weight = 0;
    let mut included = HashSet::new();
    let mut dependency_compliance = true;

    for transaction in &selected_transactions {
        if let Some(tx) = transactions.get(transaction) {
            total_fee += tx.fee;
            total_weight += tx.weight;

            if !tx.parents.iter().all(|p| included.contains(p)) {
                dependency_compliance = false;
            }

            included.insert(&tx.txid);
        }
    }

    (
        method_name.to_string(),
        total_fee,
        total_weight,
        selected_transactions.len(),
        dependency_compliance,
        elapsed_time,
    )
}

pub fn print_results(results: Vec<(String, u64, u64, usize, bool, f64)>) {
    println!(
        "{:<25} | {:>12} | {:>12} | {:>14} | {:^15} | {:>10}",
        "Method", "Total Fee", "Total Weight", "# Transactions", "Dependencies OK", "Time (s)"
    );
    println!("{}", "-".repeat(95));

    for (method, total_fee, total_weight, num_tx, dependency_ok, time) in results {
        println!(
            "{:<25} | {:>12} | {:>12} | {:>14} | {:^15} | {:>10.4}",
            method,
            format!("{:?}", total_fee),
            format!("{:?}", total_weight),
            format!("{:?}", num_tx),
            dependency_ok,
            time
        );
    }
}

pub fn check_duplicate_transactions(block_transactions: Vec<String>) -> bool {
    let mut seen_transactions = HashSet::new();

    for tx in block_transactions {
        if !seen_transactions.insert(tx) {
            println!("length of seen_transaction {}" , seen_transactions.len());
            
            return false;
        }
    }


    // let mut transaction_count: HashMap<String, u8> = HashMap::new();

    // for tx in &block_transactions {
    //     *transaction_count.entry(tx.clone()).or_insert(0) += 1;
    // }

    // for tx in &transaction_count {
    //     if *tx.1 > 1 {
    //         print!("{:?}", tx.0);
    //     }
    // }

    // No duplicates found
    true
}
