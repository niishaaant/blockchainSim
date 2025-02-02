#ifndef WALLET_H
#define WALLET_H

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <ctime>
#include <iomanip>

using namespace std;

class Transaction
{
public:
    string id;
    string sender;
    string receiver;
    double amount;
    string signature;

    void signTransaction(const string &privateKey);
    string toString() const;
};

class Wallet
{
public:
    string publicKey;
    string privateKey;

    Wallet();
    Transaction createTransaction(const string &receiver, double amount);
    void showWallet() const;

private:
    bool isValidAddress(const string &address);
    static void generateECDSAKeyPair(string &pubKey, string &privKey);
};

#endif // WALLET_H