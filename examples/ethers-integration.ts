const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const ethers = require('ethers');
const EthereumUtil = require('ethereumjs-util');

// Generate a new ECDSA key pair
const keyPair = ec.genKeyPair();
console.log(keyPair.getPrivateKey());
console.log(keyPair.getPublic().encode('hex', false));

// Get the public key and derive the Ethereum address
const publicKey = keyPair.getPublic();
const address = EthereumUtil.publicToAddress(publicKey.encode('hex', false), true);
const ethereumAddress = EthereumUtil.bufferToHex(address);

console.log('Derived Ethereum Address:', ethereumAddress);

// Get the private key in hex
const privateKey = keyPair.getPrivate().toString('hex');

// Instantiate a new Wallet instance
const wallet = new ethers.Wallet(privateKey);

// Define the transaction
const transaction = {
    to: '0x32Be343B94f860124dC4fEe278FDCBD38C102D88', // Replace with the recipient address
    value: ethers.utils.parseEther('0.01'), // Ether to send
};

// Sign the transaction
wallet.signTransaction(transaction).then(signedTransaction => {
    console.log('Signed Transaction:', signedTransaction);

    // Send the transaction
    const provider = ethers.getDefaultProvider('mainnet'); // Or any other network
    provider.sendTransaction(signedTransaction).then(tx => {
        console.log('Transaction Hash:', tx.hash);
    }).catch(error => {
        console.error('Error:', error);
    });
}).catch(error => {
    console.error('Error:', error);
});