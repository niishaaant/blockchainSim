#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <memory>
#include "Wallet.h" // Include Wallet.h

using namespace std;

class Block
{
public:
    vector<Transaction> data;
    time_t timestamp;
    string previousHash;
    string hash;
    string miner;
    int nonce;

    Block() : data(), timestamp(0), previousHash(""), hash(""), nonce(0) {}

    Block(const vector<Transaction> &data, const string &prevHash, const string &miner = "")
        : data(data), previousHash(prevHash), nonce(0)
    {
        timestamp = time(nullptr);
        hash = calculateHash();
    }

    string calculateHash() const
    {
        string input = serializeTransactions(data) + to_string(timestamp) + previousHash + to_string(nonce);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, input.c_str(), input.size());
        SHA256_Final(hash, &sha256);

        stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        {
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    void setNonce(int newNonce)
    {
        nonce = newNonce;
        hash = calculateHash();
    }

    string serializeTransactions(const vector<Transaction> &data) const
    {
        std::ostringstream oss;
        for (const auto &transaction : data)
        {
            oss << transaction.toString() << "\n";
        }
        return oss.str();
    }
};

class Blockchain
{
public:
    Wallet genesisWallet;

    string mostRecentHash;

    Blockchain(Wallet &w) : genesisWallet(w)
    {
        string address = genesisWallet.publicKey;
        Block genesisBlock = createGenesisBlock(address);
        chain[genesisBlock.hash] = genesisBlock;
        mostRecentHash = genesisBlock.hash;
    }

    void printChain() const
    {
        for (const auto &pair : chain)
        {
            const Block &block = pair.second;
            cout << "\n\nBlock " << "Data: " << serializeTransactions(block.data) << ", \n"
                 << "Timestamp: " << block.timestamp << ", \n"
                 << "Previous Hash: " << block.previousHash << ", \n"
                 << "Hash: " << block.hash << "]\n\n\n";
        }
    }

    unordered_map<string, Block> getChian() const
    {
        return chain;
    }

    void updateFrom(const Blockchain &other)
    {
        chain = other.chain;
        mostRecentHash = other.mostRecentHash;
    }

    void addBlock(const Block &newBlock)
    {
        chain[newBlock.hash] = newBlock;
        mostRecentHash = newBlock.hash;
    }

private:
    unordered_map<string, Block> chain;

    Block createGenesisBlock(const string address)
    {
        Transaction genesisTransaction;
        genesisTransaction.id = "0";
        genesisTransaction.sender = "0000000000000000000000000000000000000000000000000000000000000000";
        genesisTransaction.receiver = address;
        genesisTransaction.amount = 1000.0;
        genesisTransaction.signature = "";

        vector<Transaction> genesisTransactions = {genesisTransaction};
        return Block(genesisTransactions, "0000000000000000000000000000000000000000000000000000000000000000");
    }

    string serializeTransactions(const vector<Transaction> &data) const
    {
        std::ostringstream oss;
        for (const auto &transaction : data)
        {
            oss << transaction.toString();
        }
        return oss.str();
    }
};

class Node
{
public:
    string nodeId;
    Node(const string &id, Wallet &w) : nodeId(id), blockchain(make_shared<Blockchain>(w))
    {
        balancesTemp[blockchain->genesisWallet.publicKey] = 1000.0;
        balances[blockchain->genesisWallet.publicKey] = 1000.0;
    }

    Node(const Node &) = delete;
    Node &operator=(const Node &) = delete;

    void printBlockchain() const
    {
        blockchain->printChain();
    }

    unordered_map<string, Block> getBlockchain() const
    {
        return blockchain->getChian();
    }

    double getBalance(const string &address)
    {
        if (balances.find(address) == balances.end())
        {
            cout << "Address not found." << endl;
            return 0;
        }
        cout << "Balance of " << address << " is " << balances.at(address) << endl;
        return balances.at(address);
    }

    void printMemPool() const
    {
        for (const auto &tx : memPool)
        {
            cout << "Transaction " << tx.id << " from " << tx.sender << " to " << tx.receiver
                 << " of amount " << tx.amount << " with signature " << tx.signature << endl;
        }
    }

    void receiveBlock(const Block &block)
    {
        lock_guard<mutex> guard(unverifiedBlocksMutex);
        unverifiedBlocks.push_back(block);
    }

    void verifyReceivedBlock()
    {
        for (const auto &block : unverifiedBlocks)
        {
            if (verifyBlockAndAdd(block, true))
            {
                for (const auto &tx : block.data)
                {
                    auto it = remove_if(memPool.begin(), memPool.end(), [&tx](const Transaction &memTx)
                                        { return memTx.id == tx.id; });
                    memPool.erase(it, memPool.end());
                }

                for (const auto &tx : block.data)
                {
                    balancesTemp[tx.sender] -= tx.amount;
                    balancesTemp[tx.receiver] += tx.amount;
                    balances[tx.sender] -= tx.amount;
                    balances[tx.receiver] += tx.amount;
                }

                cout << "Block received and added to the blockchain." << endl;

                lock_guard<mutex> guard(unverifiedBlocksMutex);
                auto it = remove_if(unverifiedBlocks.begin(), unverifiedBlocks.end(), [&block](const Block &unverifiedBlock)
                                    { return unverifiedBlock.hash == block.hash; });
                unverifiedBlocks.erase(it, unverifiedBlocks.end());

                syncWithPeers();
            }
            else
            {
                cout << "Received block is invalid." << endl;
                lock_guard<mutex> guard(unverifiedBlocksMutex);
                auto it = remove_if(unverifiedBlocks.begin(), unverifiedBlocks.end(), [&block](const Block &unverifiedBlock)
                                    { return unverifiedBlock.hash == block.hash; });
                unverifiedBlocks.erase(it, unverifiedBlocks.end());
            }
        }
    }

    void syncWithPeers()
    {
        for (const auto &peerr : peers)
        {
            Node *peer = peerr;
            string prevHashPeer = peer->blockchain->mostRecentHash;
            string prevHashLocal = blockchain->mostRecentHash;
            const auto &peerChain = peer->blockchain->getChian();
            const auto &localChain = blockchain->getChian();

            if (peerChain.size() < localChain.size())
            {
                continue;
            }

            if (prevHashPeer == blockchain->mostRecentHash)
            {
                while (prevHashPeer != "0000000000000000000000000000000000000000000000000000000000000000" && prevHashLocal != "0000000000000000000000000000000000000000000000000000000000000000")
                {
                    verifyBlockHeader(peerChain.at(prevHashPeer), prevHashPeer, prevHashLocal);
                    prevHashPeer = peerChain.at(prevHashPeer).previousHash;
                    prevHashLocal = localChain.at(prevHashLocal).previousHash;
                }
                if (prevHashPeer == "0000000000000000000000000000000000000000000000000000000000000000" && prevHashLocal == "0000000000000000000000000000000000000000000000000000000000000000")
                {
                    verifyBlockHeader(peerChain.at(prevHashPeer), prevHashPeer, prevHashLocal);
                    cout << "Local chain is up to date with peer's chain." << endl;
                    return;
                }
            }

            bool isValidChain = true;

            prevHashPeer = peer->blockchain->mostRecentHash;

            while (prevHashPeer != "0000000000000000000000000000000000000000000000000000000000000000")
            {
                if (!verifyBlockHeader(peerChain.at(prevHashPeer), prevHashPeer))
                {
                    isValidChain = false;
                    break;
                }
                prevHashPeer = peerChain.at(prevHashPeer).previousHash;
            }
            blockchain->updateFrom(*peer->blockchain);
            if (isValidChain)
            {
                if (peerChain.size() == localChain.size())
                {
                    // Handle Fork
                }
                else
                {
                    blockchain->updateFrom(*peer->blockchain);
                    balances = peer->balances;
                    balancesTemp = peer->balancesTemp;
                    memPool = peer->memPool;
                    cout << "Local chain replaced with peer's chain." << endl;
                }
            }
            else
            {
                cout << "Peer's chain is invalid." << endl;
            }
        }
    }

    bool verifyBlockHeader(const Block &block, const string &prevHash, const string &currentHash = "") const
    {
        // If the hashes do not match, perform full verification
        if (block.hash != block.calculateHash())
        {
            cout << "Block hash is invalid." << endl;
            return false;
        }

        // Check if the current hash matches the block's hash
        if (currentHash == block.hash)
        {
            cout << "Block header is valid based on hash match." << endl;
            return true;
        }

        if (block.previousHash != prevHash)
        {
            cout << "Block's previous hash does not match the provided previous hash." << endl;
            return false;
        }

        string target(difficulty, '0');
        if (block.hash.substr(0, difficulty) != target)
        {
            cout << "Block hash does not meet the difficulty target." << endl;
            return false;
        }

        cout << "Block header is valid after full verification." << endl;
        return true;
    }

    // For wallets as it is
    void addTransactionToMemPool(const Transaction &tx)
    {
        lock_guard<mutex> guard(memPoolMutex);
        memPool.push_back(tx);
    }

    void runMiner()
    {
        while (true)
        {
            Block minedBlock = mineBlock();
            if (minedBlock.data.size() > 0)
            {
                lock_guard<mutex> guard(unverifiedBlocksMutex);
                if (verifyBlockAndAdd(minedBlock))
                {
                    cout << "Mined Block Hash: " << minedBlock.hash << endl;
                    this_thread::sleep_for(chrono::seconds(5)); // Wait before syncing
                    syncWithPeers();                            // Sync with peers after successful mining
                }
                else
                {
                    cout << "Block mining failed." << endl;
                }
            }
            else
            {
                cout << "Not enough transactions to mine a block." << endl;
            }
            blockchain->printChain();
            this_thread::sleep_for(chrono::seconds(5)); // Adjust sleep duration as needed
        }
    }

    void runBlockValidator()
    {
        while (true)
        {
            {
                if (!unverifiedBlocks.empty())
                {
                    verifyReceivedBlock();
                }
            }
            this_thread::sleep_for(chrono::seconds(1)); // Adjust sleep duration as needed
        }
    }

    void addPeer(Node &peer)
    {
        peers.push_back(&peer);
    }

private:
    shared_ptr<Blockchain> blockchain;
    unordered_map<string, double> balances;
    mutable mutex memPoolMutex;
    mutable mutex unverifiedBlocksMutex;
    vector<Block> unverifiedBlocks;
    vector<Node *> peers;

    vector<Transaction> memPool;
    unordered_map<string, double> balancesTemp;

    int difficulty = 4;

    bool verifyTransaction(const Transaction &tx, size_t index, bool isIncoming = false) const
    {
        if (balances.find(tx.sender) == balances.end() || balances.at(tx.sender) < tx.amount)
        {
            cout << "Insufficient balance for transaction from " << tx.sender << " to " << tx.receiver << endl;
            return false;
        }

        if (!verifySignature(tx))
        {
            cout << "Invalid signature for transaction from " << tx.sender << " to " << tx.receiver << endl;
            return false;
        }

        if (!isIncoming)
        {
            for (size_t i = 0; i < memPool.size(); ++i)
            {
                if (i != index && memPool[i].id == tx.id)
                {
                    cout << "Duplicate transaction detected with ID " << tx.id << endl;
                    return false;
                }
            }
        }

        if (tx.amount <= 0 || tx.sender.empty() || tx.receiver.empty())
        {
            cout << "Invalid transaction format from " << tx.sender << " to " << tx.receiver << endl;
            return false;
        }

        cout << "=============> Transaction Passes \n";

        return true;
    }

    Block mineBlock()
    {
        if (memPool.size() < 5)
        {
            cout << "Not enough transactions to mine a block. Need at least 5 transactions." << endl;
            return Block();
        }

        vector<Transaction> blockData;
        size_t index = 0;

        while (blockData.size() < 5 && index < memPool.size())
        {
            if (verifyTransaction(memPool[index], index))
            {
                blockData.push_back(memPool[index]);
                index++;
            }
            else
            {
                cout << "Invalid transaction detected at index " << index << ". Removing transaction." << endl;
                memPool.erase(memPool.begin() + index);
            }
        }

        if (blockData.size() < 5)
        {
            cout << "Not enough valid transactions to mine a block. Need at least 5 valid transactions." << endl;
            return Block();
        }

        for (const auto &tx : blockData)
        {
            balancesTemp[tx.sender] -= tx.amount;
            balancesTemp[tx.receiver] += tx.amount;
        }

        Block newBlock(blockData, blockchain->mostRecentHash, nodeId);

        string target(difficulty, '0');
        while (newBlock.hash.substr(0, difficulty) != target)
        {
            newBlock.setNonce(newBlock.nonce + 1);
        }

        return newBlock;
    }

    void broadcastBlock(const Block &block)
    {
        for (auto &peer : peers)
        {
            peer->receiveBlock(block);
        }
    }

    bool verifyBlockAndAdd(const Block &block, bool isIncoming = false)
    {
        lock_guard<mutex> guard(memPoolMutex);
        // Check if the block is a default block
        if (block.data.empty() && block.timestamp == 0 && block.previousHash.empty() && block.hash.empty() && block.nonce == 0)
        {
            cout << "Default block detected. Block is invalid." << endl;
            return false;
        }

        // Check if the block's hash is correct
        if (block.hash != block.calculateHash())
        {
            cout << "Block hash is invalid." << endl;
            return false;
        }

        // Check if the block's previous hash matches the most recent hash in the blockchain
        if (block.previousHash != blockchain->mostRecentHash)
        {
            cout << "Block's previous hash does not match the most recent hash in the blockchain." << endl;
            return false;
        }

        // Check if the block's transactions are valid
        for (size_t i = 0; i < block.data.size(); ++i)
        {
            if (!verifyTransaction(block.data[i], i, isIncoming))
            {
                cout << "Invalid transaction detected in block at index " << i << "." << endl;
                return false;
            }
        }

        // Check if the block's hash meets the difficulty target
        string target(difficulty, '0');
        if (block.hash.substr(0, difficulty) != target)
        {
            cout << "Block hash does not meet the difficulty target." << endl;
            return false;
        }

        cout << "Block is valid." << endl;

        blockchain->addBlock(block);
        memPool.erase(memPool.begin(), memPool.begin() + 5);
        balances = balancesTemp;

        broadcastBlock(block);

        return true;
    }

    // Utility Functions

    bool verifySignature(const Transaction &txn) const
    {
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
        BIO *bio = BIO_new_mem_buf(txn.sender.data(), txn.sender.size());
        PEM_read_bio_EC_PUBKEY(bio, &key, nullptr, nullptr);
        BIO_free(bio);

        if (key == nullptr)
        {
            cout << "Failed to create EC Key from public key string." << endl;
            return false;
        }

        unsigned char hash[32];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, (txn.sender + txn.receiver + to_string(txn.amount)).c_str(), txn.sender.size() + txn.receiver.size() + sizeof(txn.amount));
        SHA256_Final(hash, &sha256);

        string r_str = txn.signature.substr(0, txn.signature.size() / 2);
        string s_str = txn.signature.substr(txn.signature.size() / 2);

        BIGNUM *r = nullptr;
        BIGNUM *s = nullptr;
        BN_hex2bn(&r, r_str.c_str());
        BN_hex2bn(&s, s_str.c_str());

        ECDSA_SIG *sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(sig, r, s);

        int verifyStatus = ECDSA_do_verify(hash, sizeof(hash), sig, key);

        ECDSA_SIG_free(sig);
        EC_KEY_free(key);

        return verifyStatus == 1;
    }
};

// int main()
// {
//     // Node node("Node1");

//     // Wallet wallet1 = Blockchain::getInstance().genesisWallet, wallet2, wallet3;

//     // node.addTransactionToMemPool(wallet1.createTransaction(wallet2.publicKey, 1.0));
//     // node.addTransactionToMemPool(wallet1.createTransaction(wallet2.publicKey, 1.0));
//     // node.addTransactionToMemPool(wallet1.createTransaction(wallet2.publicKey, 1.0));
//     // node.addTransactionToMemPool(wallet2.createTransaction(wallet3.publicKey, 100.0));
//     // node.addTransactionToMemPool(wallet1.createTransaction(wallet2.publicKey, 1.0));
//     // node.addTransactionToMemPool(wallet1.createTransaction(wallet2.publicKey, 1.0));

//     // node.printMemPool();

//     // cout << "\n\n"
//     //      << Blockchain::getInstance().mostRecentHash << "\n\n";

//     // Block minedBlock = node.mineBlock();

//     // cout << "\n\n"
//     //      << Blockchain::getInstance().mostRecentHash << "\n\n";

//     // if (minedBlock.data.size() > 0)
//     // {
//     //     cout << "Mined Block Hash: " << minedBlock.hash << endl;
//     // }
//     // else
//     // {
//     //     cout << "Block mining failed." << endl;
//     // }

//     // node.getBalance(wallet1.publicKey);

//     // cout << "\n\n"
//     //      << Blockchain::getInstance().mostRecentHash << "\n\n";

//     // node.verifyBlockAndAdd(minedBlock);

//     // node.printBlockchain();

//     // node.getBalance(wallet1.publicKey);

//     return 0;
// }