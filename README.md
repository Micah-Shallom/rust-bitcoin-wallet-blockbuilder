# Advanced Bitcoin Protocol Implementation

## Project Overview

This project represents a comprehensive suite of Bitcoin protocol implementations, focusing on two critical components of the Bitcoin ecosystem:

1. **Signet Wallet System**
2. **Block Transaction Selection**

Both implementations are crafted in Rust, demonstrating advanced blockchain interaction capabilities, cryptographic operations, and complex algorithmic problem-solving.

## System Architecture

### 1. Signet Wallet Implementation

#### Key Technical Capabilities

- **BIP32 Hierarchical Deterministic Wallet**

  - Custom cryptographic key derivation
  - Support for hardened and non-hardened derivation paths
  - Advanced key management across multiple derivation indexes

- **Segregated Witness (SegWit) Transaction Handling**

  - Native P2WPKH (Pay-to-Witness-Public-Key-Hash) transaction support
  - Advanced P2WSH (Pay-to-Witness-Script-Hash) multisig transaction creation

#### Wallet Functionalities

- Wallet state recovery
- Transaction construction and signing
- Blockchain transaction scanning
- Complex cryptographic operations

#### Wallet Implementation Details

##### **Balance Recovery**

- Took an extended private key and derivation path to generate **2000 public key addresses**.
- Fetched transactions from the **first 300 blocks**.
- Retrieved unspent UTXOs (Unspent Transaction Outputs).
- Computed the total balance of the wallet by summing up all available UTXOs.

##### **Spending Transactions**

- Extended the wallet program to **spend coins** using a two-step transaction process:

  **Step 1: Spending from P2WPKH to P2WSH Multisig**
  - Recovered wallet state: **2000 key pairs and all unspent coins**.
  - Created a **2-of-2 multisig script** from the first two keys (indexes **0 & 1**).
  - Computed the **P2WSH witness program** from the script.
  - Constructed a transaction that:
    - Spends from a **single-key P2WPKH**.
    - Funds a **P2WSH multisig output** with **0.01 BTC**.
    - Sends the remaining balance as **change (minus fee)** to the 0th key’s **public key hash witness program**.
  - Computed **SIGHASH\_ALL transaction digest** as per **BIP 143**.
  - Signed the digest using the key responsible for the spent coin.
  - Created a **transaction witness** with the signature and public key.
  - Serialized the transaction, computed the **txid**, and returned the complete **hex-encoded transaction**.
  
  **Step 2: Spending from P2WSH Multisig**
  - Spent the **P2WSH multisig output** from the first transaction.
  - Created an **OP\_RETURN output script** encoding a **name or pseudonym** in ASCII.
  - Sent **0 BTC** to the OP\_RETURN output.
  - Ensured a **change output and fee**, reusing the **0th key**.
  - Serialized the final transaction and returned the **hex-encoded string**.

### 2. Block Builder Transaction Selection

### Overview of the Problem

Bitcoin miners face a complex optimization challenge when constructing blocks: selecting a set of transactions from the mempool that maximizes total fees while respecting critical constraints:

- Total block weight must not exceed **4,000,000 weight units**.
- All transaction **dependencies** must be respected.
- No transaction can appear more than once.
- Transactions must appear in a specific **order**.

### Detailed Implementation Stages

#### 1. Mempool Data Parsing

**Technical Approach:**

- Used Rust's `csv` crate for robust CSV parsing.
- Created a `Transaction` struct to represent each mempool entry:
  ```rust
  struct Transaction {
      txid: String,
      fee: u64,
      weight: u64,
      parents: Vec<String>,
      children: Vec<String>,
      fee_density: f64
  }
  ```

**Key Parsing Challenges:**

- Handling transactions with zero or multiple parents.
- Computing fee density (**fee/weight ratio**).
- Validating input data integrity.

#### 2. Dependency Graph Construction

**Graph Representation:**

- Utilized `petgraph` library for efficient graph management.
- Created a **Directed Acyclic Graph (DAG)** to model transaction dependencies.
- Implemented **cycle detection** to prevent invalid transaction sets.

**Topological Sorting Strategy:**

- Used **Kahn's algorithm** for reliable dependency resolution.
- Ensures **parent transactions precede children**.
- Handles complex multi-level dependency chains.

#### 3. Transaction Selection Algorithms

Implemented three sophisticated selection strategies:

1. **Greedy Solution**

   - Prioritizes transactions by **fee-to-weight ratio**.
   - Fast, computationally efficient.
   - May not always produce optimal results.

2. **Fractional Knapsack Heuristic**

   - Dynamically evaluates transaction inclusion.
   - Balances fee maximization with weight constraints.

3. **Combined Approach**

   - Hybrid method leveraging strengths of both **greedy and knapsack** strategies.

#### 4. Block Construction Validation

**Constraint Enforcement:**

- Verify total block weight ≤ **4,000,000 units**.
- Confirm **no duplicate transactions**.
- Ensure all **transaction dependencies** are satisfied.

## Compliance and Standards

### Wallet Implementation

Adheres to multiple Bitcoin Improvement Proposals (BIPs):

- **BIP 32**: Hierarchical Deterministic Wallets.
- **BIP 141**: Segregated Witness.
- **BIP 143**: Transaction Signature Verification.
- **BIP 147**: CHECKMULTISIG Signature Verification.

### Block Builder

Follows **Bitcoin Core** block construction guidelines:

- Maximum **block weight of 4,000,000 weight units**.
- Respect for **transaction dependencies**.
- Optimization of **miner fees**.

## Project Structure

```
bitcoin-protocol/
├── solution/
│   ├── rust/
│   │   ├── balance/
│   │   ├── spend/
│   │   ├── block_selection/
│   └── main.rs
├── Cargo.toml
└── README.md
```

## System Requirements

- **Rust Programming Language (Stable Channel)**
- **Bitcoin Core (Signet Network Configuration)**
- **Basic cryptographic libraries**

## Installation and Usage

```bash
# Clone the repository
git clone https://github.com/rust-bitcoin-wallet-blockbuilder.git

# Navigate to project directory
cd rust-bitcoin-wallet-blockbuilder/solution/rust

# Build the project
# Go into balance, spend, or block_selection directories and run:
cargo build --release
```

## Contribution Guidelines

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Submit a detailed pull request.
5. Ensure all tests pass.

## License

[Insert Appropriate Open-Source License]

## Disclaimer

This implementation is for **educational and research purposes**. Exercise caution when dealing with cryptocurrency transactions.

## Contact and Support

For questions, suggestions, or collaboration:

- Email: [micahshallom@gmail.com](mailto\:micahshallom@gmail.com)

