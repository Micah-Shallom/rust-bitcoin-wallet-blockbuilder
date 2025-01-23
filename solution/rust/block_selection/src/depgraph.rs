// ##############################################
// #           Dependency Graph Module          #
// # This module contains functions and structs #
// # for building and analyzing the dependency  #
// # graph of transactions.                     #
// ##############################################
use crate::parser::Transaction;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

#[derive(Debug)]
struct HeapItem {
    fee: u64,
    weight: u64,
    txid: String,
}

impl Ord for HeapItem {
    /// compare two heapitems based on their fee to weight ration
    /// using crossmultiplication to avoid floating-point inaccuracy
    fn cmp(&self, other: &Self) -> Ordering {
        (self.fee * other.weight).cmp(&(self.weight * other.fee))
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.fee * other.weight == other.fee * self.weight
    }
}

impl Eq for HeapItem {}

pub fn build_and_sort(transactions: &HashMap<String, Transaction>) -> Vec<String> {
    //compute the in-degree for each transaction
    let mut in_degree: HashMap<&String, usize> = transactions
        .iter()
        .map(|(txid, tx)| {
            let count = tx
                .parents
                .iter()
                .filter(|p| transactions.contains_key(*p))
                .count();
            (txid, count)
        })
        .collect();

    // initialize the prioirity queue with zero-in-degree transactons
    let mut heap = BinaryHeap::new();
    for (txid, tx) in transactions.iter() {
        if in_degree[txid] == 0 {
            heap.push(HeapItem {
                fee: tx.fee,
                weight: tx.weight,
                txid: txid.clone(),
            })
        }
    }

    //perform topological sorting with priority queue
    let mut topological_order = Vec::new();
    while let Some(item) = heap.pop() {
        let txid = item.txid;
        topological_order.push(txid.clone());

        if let Some(tx) = transactions.get(&txid) {
            for child in &tx.children {
                if let Some(degree) = in_degree.get_mut(child) {
                    *degree -= 1;
                    if *degree == 0 {
                        let child_tx = &transactions.get(child).unwrap();
                        heap.push(HeapItem {
                            fee: child_tx.fee,
                            weight: child_tx.weight,
                            txid: child.clone(),
                        })
                    }
                }
            }
        }
    }

    // if let Some(val) = heap.pop(){
    //     println!("{:?}", val);
    //     println!("{:?}", in_degree[&val.txid]);
    // }

    topological_order
}
