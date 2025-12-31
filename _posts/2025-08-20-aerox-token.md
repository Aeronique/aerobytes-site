---
layout: writeup
title: "AeroX: Building and Deploying My First ERC-20 Token"
date: 2025-08-20
category: "RESEARCH"
tags: ["blockchain", "solidity", "smart-contracts", "web3"]
permalink: /writeups/aerox-token/
excerpt: "Exploring blockchain security by building and deploying an ERC-20 token on the Sepolia testnet. Understanding smart contract vulnerabilities, transaction security, and the fundamentals of decentralized systems."
---

<img src="/assets/images/AeroX.png" alt="AeroX Token" style="max-width: 600px; margin: 2rem auto; display: block;">

# AeroX: Building and Deploying My First ERC-20 Token

Understanding blockchain security means understanding how blockchain actually works. So I built my own cryptocurrency token from scratch and deployed it to a live testnet.

## Why Build a Token?

In cybersecurity, you can't properly defend what you don't understand. The same goes for blockchain. With cryptocurrency scams, DeFi exploits, and smart contract vulnerabilities happening constantly, I wanted to understand the technology myself.

Building AeroX was about learning how smart contracts work, what can go wrong, and how attackers exploit these systems. The best way to learn that? Build one yourself.

## What is AeroX?

AeroX is a simple ERC-20 token deployed on the Sepolia testnet (Ethereum's testing network). It's practice cryptocurrency with no real monetary value, but it functions exactly like real tokens on the Ethereum mainnet.

**Contract Details:**
- Name: AeroX
- Symbol: AEROX
- Total Supply: 1,000,000 tokens
- Network: Sepolia Testnet
- Contract Address: `0x2401497657e2dFd81e3B6Eb0287Dbbf059552969`
- Verified on Etherscan: [View Source Code](https://sepolia.etherscan.io/token/0x2401497657e2dFd81e3B6Eb0287Dbbf059552969)

## The Technical Build

### Development Stack

I built AeroX using the Hardhat development environment, which is the industry standard for Ethereum smart contract development. The stack included:

- Solidity (smart contract programming language)
- Hardhat (development environment for compiling, testing, and deploying)
- OpenZeppelin (audited, secure smart contract libraries)
- Ethers.js (library for interacting with Ethereum)
- Infura (node provider for connecting to Sepolia testnet)

### Smart Contract Implementation

The token contract itself is straightforward, using OpenZeppelin's audited ERC-20 implementation:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract AeroX is ERC20 {
    constructor(uint256 initialSupply) ERC20("AeroX", "AEROX") {
        _mint(msg.sender, initialSupply);
    }
}
```

This contract handles three main functions:
1. Inherits from OpenZeppelin's ERC-20 standard (includes all standard token functions)
2. Sets the token name and symbol
3. Mints the initial supply to the deployer's address

Using OpenZeppelin's implementation rather than writing everything from scratch is standard in production. Their contracts have been audited extensively and are used by major DeFi projects.

### Deployment Process

Deploying to Sepolia required several steps:

**Setting up the environment:**
```javascript
// hardhat.config.js
require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

module.exports = {
  solidity: "0.8.20",
  networks: {
    sepolia: {
      url: process.env.SEPOLIA_URL,
      accounts: [process.env.PRIVATE_KEY]
    }
  }
};
```

**Writing the deployment script:**
```javascript
// scripts/deploy.js
async function main() {
  const initialSupply = ethers.parseEther("1000000");
  const AeroX = await ethers.getContractFactory("AeroX");
  const aerox = await AeroX.deploy(initialSupply);
  
  await aerox.waitForDeployment();
  console.log("AeroX deployed to:", await aerox.getAddress());
}
```

**Deploying to testnet:**
```bash
npx hardhat run scripts/deploy.js --network sepolia
```

**Verifying on Etherscan:**
```bash
npx hardhat verify --network sepolia 0x2401497657e2dFd81e3B6Eb0287Dbbf059552969 "1000000000000000000000000"
```

Verification publishes the source code publicly on Etherscan, allowing anyone to audit the contract and verify it matches what's deployed on-chain.

## Security Considerations I Learned

Building this project taught me several important security lessons about blockchain:

### Immutability is Permanent

Once deployed, smart contracts cannot be modified. If there's a bug in the code, you can't just patch it like traditional software. This makes pre-deployment security auditing something you can't skip.

### Private Keys

Your private key is your identity on the blockchain. If someone gets your private key, they control your wallet and any contracts you've deployed. I learned to:
- Never commit private keys to version control
- Use environment variables for sensitive data
- Keep testnet and mainnet keys completely separate

### Gas Costs

Every operation on Ethereum costs gas (transaction fees). Inefficient code doesn't just run slowly, it costs real money. This forces developers to optimize in ways traditional programming doesn't require.

### Common Attack Vectors

While my simple token isn't vulnerable to reentrancy attacks, learning about these common smart contract exploits showed me how attackers think. Understanding vulnerabilities like reentrancy attacks (the DAO hack), integer overflow/underflow, front-running, and access control issues helps me recognize how DeFi protocols get exploited.

### Everything is Public

Everything on a public blockchain is transparent. All transactions, all balances, all contract interactions are publicly visible. This has huge implications for privacy and operational security.

## What I'd Do Differently

If I were building a production token, several improvements would be essential:

**Access Control:**
```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

contract AeroX is ERC20, Ownable {
    // Add admin functions with proper access control
    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}
```

**Pausability:**
```solidity
import "@openzeppelin/contracts/security/Pausable.sol";

contract AeroX is ERC20, Pausable {
    // Ability to pause transfers in emergency
    function _beforeTokenTransfer(...) internal whenNotPaused override {
        super._beforeTokenTransfer(...);
    }
}
```

**Comprehensive Testing:**
- Unit tests for all functions
- Integration tests for deployment scripts
- Gas optimization analysis
- Security audit (for anything handling real value)

## How This Relates to Cybersecurity

Understanding blockchain isn't just about cryptocurrency. From a security perspective, this knowledge helps with:

**Incident Response**

When organizations get hit with crypto ransomware or crypto-mining malware, understanding how blockchain transactions work helps trace and analyze the attack.

**Threat Intelligence**

Many threat actors use cryptocurrency for payments and money laundering. Understanding blockchain forensics helps track criminal activity.

**Smart Contract Auditing**

DeFi is a massive attack surface. Knowing how to read Solidity code and identify vulnerabilities is a valuable skill for security researchers.

**Web3 Security**

As more applications integrate blockchain technology, understanding the security implications becomes increasingly important.

## Lessons Learned

This project reinforced several important principles:

Start with tested libraries. Don't reinvent the wheel, especially in security code. OpenZeppelin's contracts are audited and widely used for good reason.

Testing needs to be thorough. In blockchain, mistakes are permanent and potentially expensive. You can't skip this step.

Understand the fundamentals. You can't secure something you don't understand. Building this from scratch forced me to learn how Ethereum actually works.

Clear documentation and code comments are essential, especially when code is publicly verifiable on-chain.

## Resources

- Live Contract: [Sepolia Etherscan](https://sepolia.etherscan.io/token/0x2401497657e2dFd81e3B6Eb0287Dbbf059552969)
- Source Code: [GitHub Repository](https://github.com/Aeronique/AeroX)
- OpenZeppelin Docs: [ERC-20 Implementation](https://docs.openzeppelin.com/contracts/erc20)
- Hardhat Documentation: [Getting Started](https://hardhat.org/getting-started)

---

Building AeroX was an educational deep dive into blockchain technology from a security perspective. While I'm not pivoting to blockchain development, understanding this technology makes me a better security analyst. The principles of immutability, cryptographic security, and decentralized trust have applications far beyond cryptocurrency.

The complete source code is public and verified on-chain. Anyone can audit it, fork it, or learn from it. That's blockchain: everything is transparent by default.
