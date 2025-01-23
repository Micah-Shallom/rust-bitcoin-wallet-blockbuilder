mod depgraph;
mod parser;
mod selection;
mod test;
mod write;

fn main() {
    let file_path: &str =
        "/home/mshallom/Documents/WorkSpaces/btrust/block-builder-Micah-Shallom/mempool.csv";
    let output_path =
        "/home/mshallom/Documents/WorkSpaces/btrust/block-builder-Micah-Shallom/solution/block.txt";
    let max_block_weight = 4_000_000;

    let mempool_transaction = parser::parse_mempool(file_path).unwrap();
    let transaction_order = depgraph::build_and_sort(&mempool_transaction);
    let block =
        selection::select_transactions(transaction_order, &mempool_transaction, max_block_weight);

    //check for duplicates in transactions introduced into the block
    if !test::check_duplicate_transactions(block.clone()) {
        panic!("Duplicate transaction present in block");
    }

    let _ = write::write_block_to_file(block, &mempool_transaction, output_path);
}

// Method                    |    Total Fee | Total Weight | # Transactions | Dependencies OK |   Time (s)
// -----------------------------------------------------------------------------------------------
// Greedy Solution           |      5704530 |      3999904 |           3178 |      true       |     0.0079
// Fractional Knapsack       |      4983743 |      3999696 |           2737 |      true       |     0.0133
// Combined Approach         |      4769114 |      3229332 |           2484 |      true       |     0.0053
