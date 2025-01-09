#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

using namespace std;

// Helper function to calculate SHA-256 hash
string calculateHash(const string &input)
{
    // Initialize a buffer to store the SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Compute the SHA-256 hash of the input string
    SHA256((unsigned char *)input.c_str(), input.size(), hash);

    // Convert the hash to a hexadecimal string representation
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    // Return the resulting hash string
    return ss.str();
}

// Transaction class represents a transfer of funds between two parties
// It holds the amount of money transferred, the payer's public key, and the payee's public key
class Transaction
{
public:
    int amount;   // Amount of money being transferred
    string payer; // Public key of the payer
    string payee; // Public key of the payee

    // Constructor to initialize a transaction with the given amount, payer, and payee
    Transaction(int amt, const string &payerKey, const string &payeeKey) : amount(amt), payer(payerKey), payee(payeeKey) {}

    // Converts the transaction details to a string format for hashing and signing
    string toString() const
    {
        stringstream ss;
        ss << "{" << "\"amount\": " << amount << ", \"payer\": \"" << payer << "\", \"payee\": \"" << payee << "\"}";
        return ss.str();
    }
};

// Block class represents an individual block in the blockchain
// Each block contains a transaction, a reference to the previous block's hash, a timestamp, and a nonce used for mining
class Block
{
public:
    int nonce;               // Random value used to vary the hash during mining
    string prevHash;         // Hash of the previous block in the chain
    Transaction transaction; // Transaction data stored in the block
    time_t ts;               // Timestamp indicating when the block was created

    // Constructor to initialize a block with the previous block's hash and a transaction
    Block(const string &previousHash, const Transaction &txn) : prevHash(previousHash), transaction(txn)
    {
        nonce = rand() % 1000000;
        ts = time(nullptr);
    }

    // Calculates the hash of the block using its content
    string calculateBlockHash() const
    {
        stringstream ss;
        ss << prevHash << transaction.toString() << ts << nonce;
        return calculateHash(ss.str());
    }

    // Returns the current hash of the block
    string hash() const
    {
        return calculateBlockHash();
    }
};

// Blockchain class (Singleton)
// Manages the entire chain of blocks and provides mechanisms for adding new blocks and maintaining chain integrity
class Blockchain
{
private:
    vector<Block> chain;
    int difficulty;

    // Private constructor for Singleton
    Blockchain()
    {
        difficulty = 4;
        chain.emplace_back("", Transaction(100, "genesis", "satoshi"));
    }

public:
    // Delete copy constructor and assignment operator to prevent copying
    Blockchain(const Blockchain &) = delete;
    Blockchain &operator=(const Blockchain &) = delete;

    // Provides access to the single instance of the Blockchain class
    static Blockchain &getInstance()
    {
        static Blockchain instance;
        return instance;
    }

    // Returns the last block in the chain
    Block getLastBlock() const
    {
        return chain.back();
    }

    // Mines a block by finding a nonce that produces a hash with the required number of leading zeros
    void mineBlock(Block &block)
    {
        string target(difficulty, '0');
        while (block.calculateBlockHash().substr(0, difficulty) != target)
        {
            block.nonce++;
        }
        cout << "Block mined: " << block.calculateBlockHash() << endl;
    }

    // Adds a new block to the blockchain after mining it
    void addBlock(const Transaction &transaction)
    {
        Block newBlock(getLastBlock().hash(), transaction);
        mineBlock(newBlock);
        chain.push_back(newBlock);
    }

    // Prints the entire blockchain to the console
    void printChain() const
    {
        for (const auto &block : chain)
        {
            cout << "Block Hash: " << block.hash() << endl;
        }
    }
};

// Wallet class represents a user's wallet in the blockchain system
// It generates a public/private keypair and allows the user to create signed transactions
class Wallet
{
public:
    RSA *keypair;      // RSA keypair for the wallet
    string publicKey;  // Public key as a string
    string privateKey; // Private key as a string

    // Constructor to generate the RSA keypair and convert them to string format
    Wallet()
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

    // Sends money to another wallet by creating and signing a transaction
    void sendMoney(int amount, const string &payeePublicKey)
    {
        Transaction transaction(amount, publicKey, payeePublicKey);
        Blockchain::getInstance().addBlock(transaction);
    }

    // Destructor to free the RSA keypair
    ~Wallet()
    {
        RSA_free(keypair);
    }
};

int main()
{
    srand(time(nullptr));

    Wallet satoshi;
    Wallet bob;
    Wallet alice;

    satoshi.sendMoney(50, bob.publicKey);
    bob.sendMoney(23, alice.publicKey);
    alice.sendMoney(5, bob.publicKey);

    Blockchain::getInstance().printChain();

    return 0;
}
