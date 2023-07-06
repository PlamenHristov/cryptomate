import { computeAddress } from "@ethersproject/transactions"
import { Wallet } from "@ethersproject/wallet"
import { parseEther, parseUnits } from "@ethersproject/units"
import { getDefaultProvider } from "@ethersproject/providers"
import { EC_CURVE, ECDSA } from "cryptomate"

const makeTransfer = async () => {
  const keyPair = ECDSA.withCurve(EC_CURVE.secp256k1).genKeyPair()
  console.log("Public key:", keyPair.getPublicKeyCompressed())

  const address = computeAddress(Buffer.from(keyPair.getPublicKeyCompressed(),"hex"))
  console.log("Derived Ethereum Address:", address)

  const wallet = new Wallet(keyPair.privateKey)

  const provider = getDefaultProvider("mainnet")

  // Define the transaction
  const transaction = {
    type: 2, // EIP-1559 transaction type
    nonce: (await provider.getTransactionCount(address)) + 1,
    chainId: provider.network.chainId, // Or any other network
    to: "0x32Be343B94f860124dC4fEe278FDCBD38C102D88", // Replace with the recipient address
    value: parseEther("0.01"), // Ether to send
    gasLimit: 21000, // vanilla transfer gasLimit
    maxPriorityFeePerGas: parseUnits("1", "gwei"), // Miner tip
    maxFeePerGas: parseUnits("30", "gwei"), // Adjust according to network requirements
  }

  // Sign the transaction
  const signedTransaction = await wallet.signTransaction(transaction)
  console.log("Signed Transaction:", signedTransaction)

  const tx = await provider.sendTransaction(signedTransaction)
  console.log("Transaction Hash:", tx.hash)
}

makeTransfer()