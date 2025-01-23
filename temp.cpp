#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <ctime>
#include <chrono>
#include <random>
#include <openssl/sha.h>

using namespace std;

// Helper function to calculate SHA-256 hash
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

// Block structure
struct Block
{
    int index;
    time_t timestamp;
    string data;
    string prevHash;
    string hash;
    int nonce;

    Block(int idx, const string &data, const string &prevHash)
        : index(idx), data(data), prevHash(prevHash), nonce(0)
    {
        timestamp = time(nullptr);
        hash = calculateHash(toString());
    }

    string toString() const
    {
        stringstream ss;
        ss << index << timestamp << data << prevHash << nonce;
        return ss.str();
    }

    void mineBlock(int difficulty)
    {
        string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target)
        {
            nonce++;
            hash = calculateHash(toString());
        }
        cout << "Block mined: " << hash << endl;
    }
};

// Message structure for communication between nodes
struct Message
{
    int senderId;
    Block block;
};

// Shared resources
queue<Message> messageQueue;
mutex queueMutex;
condition_variable queueCV;

// Node class
class Node
{
private:
    int nodeId;
    vector<Block> localBlockchain;
    int difficulty;

public:
    Node(int id, int diff) : nodeId(id), difficulty(diff)
    {
        localBlockchain.emplace_back(0, "Genesis Block", "0");
    }

    void mineBlock()
    {
        string data = "Transaction from node " + to_string(nodeId);
        Block newBlock(localBlockchain.size(), data, localBlockchain.back().hash);
        newBlock.mineBlock(difficulty);

        // Add block to message queue
        {
            lock_guard<mutex> lock(queueMutex);
            messageQueue.push({nodeId, newBlock});
            cout << "Node " << nodeId << " mined a new block and added it to the queue." << endl;
        }
        queueCV.notify_all();
    }

    void processMessages()
    {
        unique_lock<mutex> lock(queueMutex);
        queueCV.wait(lock, []
                     { return !messageQueue.empty(); });

        while (!messageQueue.empty())
        {
            Message msg = messageQueue.front();
            messageQueue.pop();
            if (msg.senderId != nodeId)
            {
                localBlockchain.push_back(msg.block);
                cout << "Node " << nodeId << " added block " << msg.block.index
                     << " from node " << msg.senderId << " to the chain." << endl;
            }
        }
    }

    void run()
    {
        while (true)
        {
            mineBlock();
            processMessages();
            this_thread::sleep_for(chrono::seconds(2));
        }
    }
};

int main()
{
    srand(time(nullptr));
    const int numNodes = 3;
    const int difficulty = 4;

    vector<thread> nodeThreads;
    vector<Node> nodes;

    // Create nodes
    for (int i = 0; i < numNodes; ++i)
    {
        nodes.emplace_back(i + 1, difficulty);
    }

    // Launch threads
    for (int i = 0; i < numNodes; ++i)
    {
        nodeThreads.emplace_back(&Node::run, &nodes[i]);
    }

    // Join threads
    for (auto &t : nodeThreads)
    {
        t.join();
    }

    return 0;
}
