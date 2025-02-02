#include <Wallet.h>
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

// class Transaction::
// {
// public:
//     string id;
//     string sender;
//     string receiver;
//     double amount;
//     string signature;

void Transaction::signTransaction(const string &privateKey)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIO *bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    PEM_read_bio_ECPrivateKey(bio, &key, nullptr, nullptr);
    BIO_free(bio);

    if (key == nullptr)
    {
        cout << "Failed to create EC Key from private key" << endl;
        return;
    }

    unsigned char hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (sender + receiver + to_string(amount)).c_str(), sender.size() + receiver.size() + sizeof(amount));
    SHA256_Final(hash, &sha256);

    ECDSA_SIG *sig = ECDSA_do_sign(hash, sizeof(hash), key);
    if (sig == nullptr)
    {
        unsigned long err = ERR_get_error();
        char err_msg[120];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        cout << "Failed to sign transaction: " << err_msg << endl;
        EC_KEY_free(key);
        return;
    }

    const BIGNUM *r;
    const BIGNUM *s;
    ECDSA_SIG_get0(sig, &r, &s);

    char *r_str = BN_bn2hex(r);
    char *s_str = BN_bn2hex(s);
    signature = string(r_str) + string(s_str);

    OPENSSL_free(r_str);
    OPENSSL_free(s_str);
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
}

string Transaction::toString() const
{
    stringstream ss;
    ss << "Transaction: " << id << ", From: " << sender << ", To: " << receiver << ", Amount: " << amount << ", Signature: " << signature;
    return ss.str();
}
// };

// class Wallet::
// {
// public:
//     string publicKey;
//     string privateKey;

Wallet::Wallet()
{
    generateECDSAKeyPair(publicKey, privateKey);
}

Transaction Wallet::createTransaction(const string &receiver, double amount)
{
    Transaction tx;
    tx.sender = publicKey;
    tx.receiver = receiver;
    tx.amount = amount;
    stringstream ss;
    ss << time(nullptr) << publicKey << receiver << amount;
    tx.id = ss.str();
    tx.signTransaction(privateKey);
    return tx;
}

void Wallet::showWallet() const
{
    cout << "Public Key: " << publicKey << endl;
    cout << "Private Key: " << privateKey << endl;
}

// private:
bool Wallet::isValidAddress(const string &address)
{
    if (address.empty())
    {
        return false;
    }
    if (address.length() != 174)
    {
        return false;
    }
    return true;
}

void Wallet::generateECDSAKeyPair(string &pubKey, string &privKey)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (key == nullptr)
    {
        cout << "Failed to create new EC Key" << endl;
        return;
    }

    if (EC_KEY_generate_key(key) == 0)
    {
        cout << "Failed to generate EC Key" << endl;
        EC_KEY_free(key);
        return;
    }

    BIO *pub = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(pub, key);
    size_t pub_len = BIO_pending(pub);
    char *pub_key = new char[pub_len + 1];
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';
    pubKey = string(pub_key);
    delete[] pub_key;
    BIO_free(pub);

    BIO *priv = BIO_new(BIO_s_mem());
    PEM_write_bio_ECPrivateKey(priv, key, nullptr, nullptr, 0, nullptr, nullptr);
    size_t priv_len = BIO_pending(priv);
    char *priv_key = new char[priv_len + 1];
    BIO_read(priv, priv_key, priv_len);
    priv_key[priv_len] = '\0';
    privKey = string(priv_key);
    delete[] priv_key;
    BIO_free(priv);

    EC_KEY_free(key);
}
// };

// int main()
// {
//     Wallet wallet1, wallet2;

//     wallet1.createTransaction(wallet2.publicKey, 10.0);

//     return 0;
// }