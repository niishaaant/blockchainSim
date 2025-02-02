# Blockchain Simulator

This project is a simple blockchain simulator implemented in C++. It includes basic functionalities such as creating wallets, generating transactions, mining blocks, and validating the blockchain. The simulator uses ECDSA for signing transactions and SHA-256 for hashing.

## Project Structure

- **main.cpp**: Entry point of the application. It initializes wallets, nodes, and starts the simulation.
- **Node.cpp**: Contains the implementation of the `Node` and `Blockchain` classes, which handle the blockchain operations.
- **Wallet.h**: Header file for the `Wallet` and `Transaction` classes.
- **Wallet.cpp**: Implementation of the `Wallet` and `Transaction` classes.

## How to Run

1. **Clone the repository**:
    ```sh
    git clone https://github.com/niishaaant/blockchainSim.git
    cd blockchainSimulator
    ```

2. **Install dependencies**:
    Ensure you have OpenSSL installed on your system. You can install it using:
    ```sh
    sudo apt-get install libssl-dev
    ```

3. **Compile the project**:
    ```sh
    g++ -o blockchainSimulator main.cpp Node.cpp Wallet.cpp -lssl -lcrypto -pthread
    ```

4. **Run the simulator**:
    ```sh
    ./blockchainSimulator
    ```

## Features

- **Wallet Creation**: Generate ECDSA key pairs for wallets.
- **Transaction Creation**: Create and sign transactions between wallets.
- **Mining**: Mine blocks and add them to the blockchain.
- **Validation**: Validate blocks and synchronize the blockchain across nodes.

## Future Improvements

- Implement a peer-to-peer network for nodes.
- Add more sophisticated consensus algorithms.
- Enhance the transaction and block validation mechanisms.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
