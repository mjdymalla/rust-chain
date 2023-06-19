use crypto_hash::{Algorithm, hex_digest, digest};
use chrono::{Utc, TimeZone};
use std::collections::VecDeque;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::mem::replace;
use std::sync::{Arc, Mutex, MutexGuard};
use ed25519_dalek::{Keypair, Signature, PublicKey, Sha512, Digest};
use rand::rngs::OsRng;
use warp::Filter;
use serde::{Serialize, Deserialize};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{Duration, sleep};
use tokio::task;
use tokio::sync::oneshot;
use hex;

struct Block {
    index: u32,
    size: u32,
    timestamp: u64,
    transactions: Vec<Transaction>,
    hash: String,
}

struct Blockchain {
    blocks: Vec<Block>,
    balances: HashMap<String, u32>, 
    max_block_size: u32,
    transaction_pool: VecDeque<Transaction>,
    proposed_block: Block,
    miner_wallet: Wallet,
}

#[derive(Serialize, Deserialize)]
struct TransactionPayload {
    from: String,
    to: String,
    amount: u32,
    rads: u32,
    signature: String,
}

struct Transaction {
    from: String,
    to: String,
    amount: u32,
    rads: u32,
    signature: Signature,
}

#[derive(Serialize)]
struct Wallet {
    public_key: String,
    private_key: String,
}

impl Blockchain {
    // create chain with genesis block
    fn apply(max_block_size: u32) -> Self {
        println!("Initialising blockchain...");

        let mut chain = Self {
            blocks: Vec::new(),
            balances: HashMap::new(),
            max_block_size,
            transaction_pool: VecDeque::new(),
            proposed_block: Block {
                index: 0,
                size: 0,
                timestamp: Utc::now().timestamp() as u64,
                transactions: Vec::new(),
                hash: String::new(),
            },
            miner_wallet: generate_keypair()
        };

        // test wallet with funds
        let wallet = generate_keypair();
        println!("pub key: {}", wallet.public_key);
        println!("priv key: {}", wallet.private_key);
        chain.balances.insert(wallet.public_key, 1000);

        // create genesis block
        let genesis_block = Block {
            index: 0,
            size: 100,
            timestamp: Utc::now().timestamp() as u64,
            transactions: Vec::new(),
            hash: String::new(),
        };

        chain.blocks.push(genesis_block);

        return chain;
    }

    // check transaction is valid, sender has appropriate funds, and is signed with private key
    fn validate_transaction(&self, transaction: &Transaction, public_key: PublicKey) -> Result<bool, String> {
        if let Some(&balance) = self.balances.get(&transaction.from) {
            if balance < transaction.amount {
                return Err(String::from("Insufficient funds"));
            }
        } else {
            return Err(String::from("Sender address does not exist"));
        }

        // check for valid signature
        let mut hasher = Sha512::new();
        hasher.update(transaction.from.as_bytes());
        hasher.update(transaction.to.as_bytes());
        hasher.update(transaction.amount.to_be_bytes());
        let signature_hash = hasher.finalize();

        if public_key.verify_strict(&signature_hash, &transaction.signature).is_err() {
            return Err(String::from("Invalid signature"));
        }

        println!("Transaction is valid");

        return Ok(true);
    }

    // add transaction to proposed block
    fn add_transaction(&mut self, transaction: Transaction) {
        // prev hash - used to create new blocks hash
        let previous_hash: String = if let Some(last_block) = self.blocks.last() {
            last_block.hash.clone()
        } else {
            String::from("00000")
        };

        // destructure incoming transaction
        let Transaction { from, to, amount, rads, signature } = transaction;

        let index = self.blocks.len() as u32;
        let timestamp = Utc::now().timestamp() as u64;
        let mut current_block = &mut self.proposed_block;

        // decrement balance of sender (sender pays for transaction)
        if let Some(balance) = self.balances.get_mut(&from) {
            *balance -= amount + rads;
        }

        // increment balance of receivers
        if let Some(balance) = self.balances.get_mut(&to) {
            *balance += amount;
        }

        // increment balance of miner
        if let Some(balance) = self.balances.get_mut(&self.miner_wallet.public_key) {
            *balance += rads;
        }

        if current_block.size + amount < self.max_block_size {
            current_block.transactions.push(Transaction { from, to, amount, rads, signature });
            current_block.size += amount;
        } else {
            // add transaction to current block
            current_block.transactions.push(Transaction { from, to, amount, rads, signature });
            // update hash of current block
            let new_hash = Self::calculate_hash(index, timestamp, &previous_hash);
            current_block.hash = new_hash;

            let replacement = Block {
                index: index + 1,
                size: 0,
                timestamp: Utc::now().timestamp() as u64,
                transactions: Vec::new(),
                hash: String::new(),
            };

            // add complete block to chain and replace with new block
            self.blocks.push(replace(&mut self.proposed_block, replacement));
        }
    }

    fn calculate_hash(index: u32, timestamp: u64, previous_hash: &str) -> String {
        let input = format!("{}{}{}", index, timestamp, previous_hash);
        return hex_digest(Algorithm::SHA256, input.as_bytes());
    }
}

// generate keypair using ed25519
fn generate_keypair() -> Wallet {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    
    Wallet {
        public_key: hex::encode(keypair.public.as_bytes()),
        private_key: hex::encode(keypair.secret.as_bytes()),
    }
}

// endpoint to generate public and private key pair
fn create_wallet() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("create_wallet")
        .map(move || warp::reply::json(&generate_keypair()))
}

// endpoint to receive transactions
fn receive_transaction(chain: Arc<Mutex<Blockchain>>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("transaction")
        .and(warp::post())
        .and(warp::body::json())
        .map(move |transaction_payload: TransactionPayload| {
            // acquire lock on chain
            let mut chain: MutexGuard<Blockchain> = chain.lock().unwrap();

            // create Signature from string
            let signature_bytes = hex::decode(&transaction_payload.signature).unwrap();
            let signature = Signature::from_bytes(&signature_bytes).unwrap();

            // create transaction
            let transaction = Transaction {
                from: transaction_payload.from,
                to: transaction_payload.to,
                amount: transaction_payload.amount,
                rads: transaction_payload.rads,
                signature,
            };

            // create public key from string
            let public_key_bytes = hex::decode(transaction.from.clone()).unwrap();
            let public_key = PublicKey::from_bytes(&public_key_bytes).unwrap();

            let validated = chain.validate_transaction(&transaction, public_key);

            match validated {
                Ok(_) => {
                    println!("Transaction received and added to pool");
                    chain.transaction_pool.push_back(transaction);
                    warp::reply::json(&"Transaction received - pending validation")
                },
                Err(err) => warp::reply::json(&err),
            }
        })
}

// transaction worker function (simulates mining)
async fn transaction_worker(chain: Arc<Mutex<Blockchain>>) -> () {
    loop {
        sleep(Duration::from_secs(5)).await;

        // acquire lock on chain
        let mut chain = chain.lock().unwrap();

        // pop transaction from queue and process
        if !chain.transaction_pool.is_empty() {
            while let Some(transaction) = chain.transaction_pool.pop_front() {
                chain.add_transaction(transaction);
            }
        } else {
            println!("No transactions to process");
        }
    }
}

#[tokio::main]
async fn main() {
    // oneshot channel to receive shutdown signal
    let (tx, rx) = oneshot::channel();
    let shutdown_sig = Arc::new(Mutex::new(tx));

    // spawn thread to listen for SIGINT
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let tx_clone = Arc::clone(&shutdown_sig);
    tokio::spawn(async move {
        sigint.recv().await;
        let sig = tx_clone.lock().unwrap();
        //let _ = sig.send(());
    });


    // initialise chain
    let chain = Blockchain::apply(100);
    let chain_mutex = Arc::new(Mutex::new(chain));
    let chain_clone = Arc::clone(&chain_mutex);

    let routes = create_wallet().or(receive_transaction(Arc::clone(&chain_clone)));

    let worker = task::spawn(transaction_worker(Arc::clone(&chain_clone)));

    let server = warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}
