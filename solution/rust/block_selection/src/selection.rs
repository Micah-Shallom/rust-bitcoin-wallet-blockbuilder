// ##############################################
// #           Transaction Selector             #
// # This module contains functions and structs #
// # for selecting transactions from the mempool#
// # that will be included in the block.        #
// ##############################################
use crate::parser::Transaction;
use crate::test::{evaluate_method, print_results};
use std::collections::{HashMap, HashSet};

pub fn select_transactions(
    topological_order: Vec<String>,
    transactions: &HashMap<String, Transaction>,
    max_weight: u64,
) -> Vec<String> {
    let greedy_solution = greedy_filter(topological_order.clone(), transactions, max_weight);
    let evaluate_greedy_solution = evaluate_method(
        "Greedy Solution",
        greedy_filter,
        topological_order.clone(),
        transactions,
        max_weight,
    );
    let knapsack_solution = evaluate_method(
        "Fractional Knapsack",
        fractional_knapsack_heuristic,
        topological_order.clone(),
        transactions,
        max_weight,
    );

    let combined_order = fractional_knapsack_heuristic(greedy_solution.clone(), transactions, max_weight);
    let combined_solution = evaluate_method(
        "Combined Approach",
        fractional_knapsack_heuristic,
        combined_order,
        transactions,
        max_weight,
    );

    let results = vec![
        evaluate_greedy_solution,
        knapsack_solution,
        combined_solution,
    ];

    print_results(results);

    greedy_solution
}

fn greedy_filter(
    topological_order: Vec<String>,
    transactions: &HashMap<String, Transaction>,
    max_weight: u64,
) -> Vec<String> {
    let mut current_weight = 0;
    let mut included = HashSet::new();
    let mut block = Vec::new();

    // let count_tx_with_no_parents = &topological_order
    //     .iter()
    //     .filter(|tx| {
    //         let transaction = transactions.get(tx.clone()).unwrap();
    //         transaction.parents.len() == 0
    //     })
    //     .count();

    for txid in &topological_order {
        // if let Some(tx) = transactions.get(&txid){}
        let tx = transactions.get(txid).unwrap();

        //verify all parents are included
        let parents_included = tx
            .parents
            .iter()
            .filter(|p| transactions.contains_key(*p))
            .all(|p| included.contains(p));

        if !parents_included {
            continue;
        }

        //check if adding this transaction exceeds  the limit of our block weight
        if current_weight + tx.weight <= 4_000_000 {
            block.push(txid.clone());
            current_weight += tx.weight;
            included.insert(txid);
        }
    }
    block
}

fn fractional_knapsack_heuristic(
    topological_order: Vec<String>,
    transactions: &HashMap<String, Transaction>,
    max_weight: u64,
) -> Vec<String> {
    let mut current_weight = 0;
    let mut included = HashSet::new();
    let mut selected = Vec::new();
    let max_weight = 4_000_000;

    // Step 1: Precompute fee-to-weight ratios and sort transactions
    let mut tx_with_ratio: Vec<_> = topological_order
        .iter()
        .map(|txid| {
            let tx = transactions.get(txid).unwrap();
            (txid.clone(), tx.fee as f64 / tx.weight as f64)
        })
        .collect();

    // Sort transactions by fee-to-weight ratio in descending order
    tx_with_ratio.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    // Step 2: Iteratively add transactions
    for (txid, _) in tx_with_ratio {
        let tx = transactions.get(&txid).unwrap();

        // Verify all parents are included
        let parents_included = tx
            .parents
            .iter()
            .filter(|p| transactions.contains_key(*p))
            .all(|p| included.contains(p));

        if !parents_included {
            continue;
        }

        // Check if adding this transaction exceeds the weight limit
        if current_weight + tx.weight <= max_weight {
            selected.push(txid.clone());
            current_weight += tx.weight;
            included.insert(txid);
        }
    }

    selected
}
