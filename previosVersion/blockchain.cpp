#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

using namespace std;

string calculateHash(const string &input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input.c_str(), input.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

class Transaction
{
public:
    int amount;
    string payer;     // Public key of the payer
    string payee;     // Public key of the payee
    string signature; // Digital signature of the transaction

    // Constructor
    Transaction(int amt, const string &payerKey, const string &payeeKey)
        : amount(amt), payer(payerKey), payee(payeeKey), signature("") {}

    string toString() const
    {
        stringstream ss;
        ss << "{" << "\"amount\": " << amount << ", \"payer\": \"" << payer
           << "\", \"payee\": \"" << payee << "\"}";
        return ss.str();
    }

    void signTransaction(RSA *keypair)
    {
        string txnHash = calculateHash(this->toString());

        unsigned char sig[256];
        unsigned int signatureLength;
        RSA_sign(NID_sha256, (const unsigned char *)txnHash.c_str(), txnHash.size(),
                 sig, &signatureLength, keypair);

        string encodedSignature(sig, sig + signatureLength);

        signature = encodedSignature;
    }
};

class Block
{
public:
    int nonce;
    string prevHash;
    Transaction transaction;
    time_t ts;

    Block(const string &previousHash, const Transaction &txn) : prevHash(previousHash), transaction(txn)
    {
        nonce = rand() % 1000000;
        ts = time(nullptr);
    }

    string calculateBlockHash() const
    {
        stringstream ss;
        ss << prevHash << transaction.toString() << ts << nonce;
        return calculateHash(ss.str());
    }

    string hash() const
    {
        return calculateBlockHash();
    }
};

class Node;

class Blockchain
{
private:
    vector<Block> chain;
    vector<unique_ptr<Node>> nodes;
    int difficulty;

    Blockchain()
    {
        difficulty = 4;
        chain.emplace_back("", Transaction(100, "genesis", "satoshi"));
    }

    bool broadcastNewBlock(const Block &newBlock)
    {
        int validCount = 0;
        int totalNodes = nodes.size();

        for (const auto &node : nodes)
        {
            if (node->verifyNewBlock(newBlock))
            {
                validCount++;
            }
        }

        if (validCount >= (totalNodes / 2.0))
        {
            cout << "Block accepted: " << validCount << " out of " << totalNodes << " nodes agree.\n";
            return true;
        }
        else
        {
            cout << "Block rejected: Only " << validCount << " out of " << totalNodes << " nodes agree.\n";
            return false;
        }
    }

    void addBlock(Block newBlock)
    {
        if (walletBalances[newBlock.transaction.payer] < newBlock.transaction.amount)
        {
            cerr << "Block rejected. Insufficient balance for transaction." << endl;
            return;
        }

        if (broadcastNewBlock(newBlock))
        {
            walletBalances[newBlock.transaction.payer] -= newBlock.transaction.amount;
            walletBalances[newBlock.transaction.payee] += newBlock.transaction.amount;

            chain.push_back(newBlock);
        }
        else
        {
            cout << "Block rejected.\n";
        }
    }

    friend class Node;

public:
    Blockchain(const Blockchain &) = delete;
    Blockchain &operator=(const Blockchain &) = delete;

    unordered_map<string, int> walletBalances;

    static Blockchain &getInstance()
    {
        static Blockchain instance;
        return instance;
    }

    Block getLastBlock() const
    {
        return chain.back();
    }

    void addNode(unique_ptr<Node> n)
    {
        nodes.push_back(std::move(n)); // Move the unique pointer into the vector
    }

    int getWalletBalance(const string &walletAddress) const
    {
        auto it = walletBalances.find(walletAddress);
        if (it != walletBalances.end())
        {
            return it->second;
        }
        return 0; // Default balance is 0 for new wallets
    }

    void printChain() const
    {
        for (const auto &block : chain)
        {
            cout << "Block Hash: " << block.hash() << endl;
        }
    }
};

class Node
{
private:
    Blockchain &blockchain;
    int nodeId;
    int difficulty;
    queue<Transaction> transactionQueue; // Queue for transactions
    mutex mtx;                           // Mutex for thread safety
    condition_variable cv;               // Condition variable for synchronization
    bool running = true;                 // Flag to control the thread loop

    // Delete copy constructor and copy assignment operator
    Node(const Node &) = delete;
    Node &operator=(const Node &) = delete;

    bool isValidTransaction(const Transaction &txn)
    {
        if (txn.amount <= 0)
        {
            cout << "Invalid transaction: amount must be greater than 0" << endl;
            return false;
        }

        if (txn.payer.empty() || txn.payee.empty())
        {
            cout << "Invalid transaction: payer and payee public keys must not be empty" << endl;
            return false;
        }

        string txnHash = calculateHash(txn.toString());

        const unsigned char *decodedSignature = (const unsigned char *)txn.signature.c_str();
        unsigned int signatureLength = txn.signature.size();

        BIO *bio = BIO_new_mem_buf((void *)txn.payer.c_str(), -1);
        RSA *rsaPublicKey = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        bool isValid = RSA_verify(NID_sha256, (const unsigned char *)txnHash.c_str(), txnHash.size(),
                                  decodedSignature, signatureLength, rsaPublicKey);

        RSA_free(rsaPublicKey);

        if (!isValid)
        {
            cerr << "Transaction verification failed. Invalid signature." << endl;
            return false;
        }

        // Validate sender's balance
        if (blockchain.getWalletBalance(txn.payer) < txn.amount)
        {
            cerr << "Transaction failed. Insufficient balance." << endl;
            return false;
        }

        return true; // Transaction is valid
    }

    void mineBlock(Block &block)
    {
        string target(difficulty, '0');
        while (block.calculateBlockHash().substr(0, difficulty) != target)
        {
            block.nonce++;
        }
        cout << "Block mined: " << block.calculateBlockHash() << endl;
    }

    void addBlock(const Transaction &transaction)
    {
        if (isValidTransaction(transaction))
        {
            Block newBlock(blockchain.getLastBlock().hash(), transaction);
            mineBlock(newBlock);
            blockchain.addBlock(newBlock);
        }
        else
        {
            cout << "Transaction rejected: " << transaction.toString() << endl;
        }
    }

public:
    Node(int id, int diff, Blockchain &bc) : nodeId(id), difficulty(diff), blockchain(bc)
    {
    }

    void addTransaction(const Transaction &txn)
    {
        if (isValidTransaction(txn))
        {
            {
                lock_guard<mutex> lock(mtx); // Lock the mutex for safe access
                transactionQueue.push(txn);  // Add transaction to the queue
            }
            cv.notify_one(); // Notify the node thread about the new transaction
            cout << "Transaction added to the queue: " << txn.toString() << endl;
        }
        else
        {
            cout << "Transaction rejected: " << txn.toString() << endl;
        }
    }

    bool verifyNewBlock(const Block &block)
    {
        if (block.prevHash != blockchain.getLastBlock().hash())
        {
            cout << "Block verification failed: Previous hash does not match.\n";
            return false;
        }

        if (block.hash().substr(0, difficulty) != string(difficulty, '0'))
        {
            cout << "Block verification failed: Proof of work is invalid.\n";
            return false;
        }

        if (!isValidTransaction(block.transaction))
        {
            cout << "Block verification failed: Invalid transaction found.\n";
            return false;
        }

        cout << "Block verification succeeded.\n";
        return true;
    }

    void run()
    {
        while (running)
        {
            if (!transactionQueue.empty())
            {
                unique_lock<mutex> lock(mtx);

                Transaction transaction = transactionQueue.front();
                transactionQueue.pop();

                lock.unlock();

                addBlock(transaction);
            }
            else
            {
                this_thread::yield();
            }
        }
    }

    void stop()
    {
        running = false;
        cv.notify_all();
    }
};

class Wallet
{
private:
    Node &node; // Reference to the node
public:
    RSA *keypair;      // RSA keypair for the wallet
    string publicKey;  // Public key as a string
    string privateKey; // Private key as a string

    Wallet(Node &n) : node(n)
    {
        keypair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);

        // Extract public key
        BIO *pub = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(pub, keypair);
        size_t pub_len = BIO_pending(pub);
        char *pub_key = new char[pub_len];
        BIO_read(pub, pub_key, pub_len);
        publicKey = string(pub_key, pub_len);

        // Extract private key
        BIO *priv = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(priv, keypair, nullptr, nullptr, 0, nullptr, nullptr);
        size_t priv_len = BIO_pending(priv);
        char *priv_key = new char[priv_len];
        BIO_read(priv, priv_key, priv_len);
        privateKey = string(priv_key, priv_len);

        // Free memory
        delete[] pub_key;
        delete[] priv_key;
        BIO_free_all(pub);
        BIO_free_all(priv);
    }

    void sendMoney(int amount, const string &payeePublicKey)
    {
        Transaction txn(amount, publicKey, payeePublicKey);

        // ==========> Send Txn to nodes <==========

        cout << "Wallet sending transaction: " << txn.toString() << endl;
        txn.signTransaction(keypair);
        node.addTransaction(txn);
    }

    ~Wallet()
    {
        RSA_free(keypair);
    }
};

int main()
{
    srand(time(nullptr));

    int noOfNodes = 8;

    vector<thread> nodeThreads;
    vector<unique_ptr<Node>> nodes;

    // Create nodes
    for (int i = 0; i < noOfNodes; ++i)
    {
        nodes.push_back(make_unique<Node>(i + 1, 4, Blockchain::getInstance()));
        Blockchain::getInstance().addNode(move(nodes.back()));
    }

    for (int i = 0; i < noOfNodes; ++i)
    {
        nodeThreads.emplace_back(&Node::run, nodes[i].get());
    }

    for (auto &node : nodeThreads)
    {
        node.join();
    }

    Wallet satoshi = Wallet(*nodes[0]);
    Wallet bob = Wallet(*nodes[1]);
    Wallet alice = Wallet(*nodes[2]);

    satoshi.sendMoney(50, bob.publicKey);
    bob.sendMoney(23, alice.publicKey);
    alice.sendMoney(5, bob.publicKey);

    Blockchain::getInstance().printChain();

    return 0;
}
