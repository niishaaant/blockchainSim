#include <iostream>
#include <thread>
#include <vector>
#include <memory>
#include "Node.cpp"
#include "Wallet.h"

using namespace std;

#include <cstdlib>
#include <ctime>

void runWallet(shared_ptr<Node> node, Wallet &wallet1, Wallet &wallet2)
{
    srand(time(0));
    Wallet *selectedWallet = (rand() % 2 == 0) ? &wallet1 : &wallet2;
    Wallet *otherWallet = (selectedWallet == &wallet1) ? &wallet2 : &wallet1;

    cout << "Selected Wallet: " << selectedWallet->publicKey << endl;
    cout << "Other Wallet: " << otherWallet->publicKey << endl;

    double balance = node->getBalance(selectedWallet->publicKey);
    if (balance > 0)
    {
        double amount = (rand() % static_cast<int>(balance)) + 1; // Ensure amount is less than balance
        Transaction tx = selectedWallet->createTransaction(otherWallet->publicKey, amount);
        node->addTransactionToMemPool(tx);
    }
}
void runWalletThread(vector<shared_ptr<Node>> nodes, Wallet &wallet1, Wallet &wallet2)
{
    while (true)
    {
        shared_ptr<Node> node = nodes[rand() % nodes.size()];
        runWallet(node, wallet1, wallet2);
        this_thread::sleep_for(chrono::seconds(10));
    }
}
int main()
{
    Wallet genesisWallet = Wallet();

    shared_ptr<Node> node1 = make_shared<Node>("Node1", genesisWallet);
    vector<shared_ptr<Node>> nodes;
    nodes.push_back(node1);

    vector<Wallet> wallets;
    for (int i = 0; i < 10; ++i)
    {
        wallets.push_back(Wallet());
    }

    for (int i = 0; i < wallets.size(); ++i)
    {
        Transaction tx = genesisWallet.createTransaction(wallets[i].publicKey, 100.0);
        node1->addTransactionToMemPool(tx);
    }

    node1->printMemPool();

    node1->runMiner();
    // node1->runMiner();

    // for (int i = 2; i <= 8; ++i)
    // {
    //     nodes.push_back(make_shared<Node>("Node" + to_string(i), genesisWallet));
    //     for (auto &node : nodes)
    //     {
    //         for (auto &peer : nodes)
    //         {
    //             if (node != peer)
    //             {
    //                 node->addPeer(*peer);
    //             }
    //         }
    //     }
    //     cout << "Blockchain of Node " << i - 1 << "before SYNC \n"
    //          << endl;
    //     nodes[i - 1]->printBlockchain();
    //     nodes[i - 1]->syncWithPeers();
    //     cout << "Blockchain of Node " << i - 1 << "after SYNC" << endl;
    //     nodes[i - 1]->printBlockchain();
    // }

    // vector<thread> walletThreads;
    // for (int i = 0; i < 5; ++i)
    // {
    //     walletThreads.push_back(thread(runWalletThread, nodes, ref(wallets[i * 2]), ref(wallets[i * 2 + 1])));
    // }

    // for (auto &t : walletThreads)
    // {
    //     t.join();
    // }

    // vector<thread> minerThreads;
    // for (auto &node : nodes)
    // {
    //     minerThreads.push_back(thread(&Node::runMiner, node));
    // }

    // for (auto &t : minerThreads)
    // {
    //     t.join();
    // }

    // vector<thread> validatorThreads;
    // for (auto &node : nodes)
    // {
    //     validatorThreads.push_back(thread(&Node::runBlockValidator, node));
    // }

    // for (auto &t : validatorThreads)
    // {
    //     t.join();
    // }

    // shared_ptr<Node> node2 = make_shared<Node>("Node2", genesisWallet);
    // shared_ptr<Node> node3 = make_shared<Node>("Node3", genesisWallet);
}