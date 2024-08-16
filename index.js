import { ethers } from "ethers";
import { promises as fs } from "fs";
import crypto from "crypto";
import readline from "readline/promises";
import { fileURLToPath } from "url";
import path from "path";
import nacl from "tweetnacl";
import { generateMnemonic, mnemonicToSeedSync } from "bip39";
import { derivePath } from "ed25519-hd-key";
import {
  Keypair,
  Connection,
  LAMPORTS_PER_SOL,
  PublicKey,
} from "@solana/web3.js";
import { HDNodeWallet } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class MultiChainWallet {
  constructor() {
    this.walletsDir = path.join(__dirname, "wallets");
    this.networksFile = path.join(__dirname, "networks.json");
    this.defaultEthereumRpcUrl = "https://mainnet.eth.cloud.ava.do";
    this.defaultSolanaRpcUrl = "https://api.mainnet-beta.solana.com";
    this.chainIdCounter = 1;
    this.networks = {};
    this.currentNetwork = null;
    this.password = null;
  }

  async initialize() {
    await this.loadNetworks();
    await this.initializeDefaultNetworks();
  }

  async setPassword(password) {
    if (!password) {
      throw new Error("Password cannot be empty.");
    }
    this.password = password;
    await this.savePassword();
  }

  async promptForPassword() {
    if (!this.password) {
      const password = await this.askQuestion("Set a new password: ");
      await this.setPassword(password);
    }
  }

  async savePassword() {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto
      .pbkdf2Sync(this.password, salt, 1000, 64, "sha512")
      .toString("hex");
    await fs.writeFile("password.json", JSON.stringify({ salt, hash }));
  }

  async verifyPassword(password) {
    try {
      const data = await fs.readFile("password.json", "utf8");
      const { salt, hash } = JSON.parse(data);
      const verifyHash = crypto
        .pbkdf2Sync(password, salt, 1000, 64, "sha512")
        .toString("hex");
      return hash === verifyHash;
    } catch (error) {
      console.error("Failed to verify password:", error.message);
      return false;
    }
  }

  encrypt(text) {
    if (!this.password) {
      throw new Error("Password is not set.");
    }
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      "aes-256-ctr",
      Buffer.from(this.password.padEnd(32, " ")),
      iv,
    );
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
  }

  decrypt(text) {
    if (!this.password) {
      throw new Error("Password is not set.");
    }
    const [ivHex, encryptedHex] = text.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const encrypted = Buffer.from(encryptedHex, "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-ctr",
      Buffer.from(this.password.padEnd(32, " ")),
      iv,
    );
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }

  async loadNetworks() {
    try {
      const data = await fs.readFile(this.networksFile, "utf8");
      this.networks = JSON.parse(data.trim() || "{}");
      this.chainIdCounter =
        Math.max(...Object.values(this.networks).map((net) => net.chainId), 0) +
        1;
    } catch (error) {
      if (error.code === "ENOENT") {
        console.log(
          `${this.networksFile} does not exist, initializing with default networks.`,
        );
        this.networks = {};
        this.chainIdCounter = 1;
      } else {
        throw error;
      }
    }
  }

  async saveNetworks() {
    await fs.writeFile(
      this.networksFile,
      JSON.stringify(this.networks, null, 2),
    );
  }

  async initializeDefaultNetworks() {
    if (!this.networks.ethereum) {
      await this.addNetwork("ethereum", this.defaultEthereumRpcUrl);
    }
    if (!this.networks.solana) {
      await this.addNetwork("solana", this.defaultSolanaRpcUrl);
    }
  }

  async addNetwork(name, rpcUrl) {
    const chainId = this.chainIdCounter++;
    this.networks[name] = { chainId, rpcUrl };
    await this.saveNetworks();
    console.log(`Added network ${name} with Chain ID ${chainId}`);
  }

  async createWallet(walletName) {
    if (!this.password) {
      throw new Error("Password must be set before creating a wallet.");
    }
    const mnemonic = generateMnemonic();
    const walletDir = path.join(this.walletsDir, walletName);

    await fs.mkdir(walletDir, { recursive: true });

    const encryptedMnemonic = this.encrypt(mnemonic);
    await fs.writeFile(
      path.join(walletDir, "wallet.json"),
      JSON.stringify({ mnemonic: encryptedMnemonic }, null, 2),
    );
    console.log(`Created wallet: ${walletName}`);
  }

  async addAccount(walletName, network) {
    if (!this.password) {
      throw new Error("Password must be set before adding an account.");
    }
    const walletDir = path.join(this.walletsDir, walletName);
    const walletFile = path.join(walletDir, "wallet.json");

    try {
      const walletData = await fs.readFile(walletFile, "utf8");
      const { mnemonic } = JSON.parse(walletData);
      const decryptedMnemonic = this.decrypt(mnemonic);

      let accountData;
      if (network === "ethereum") {
        const wallet = HDNodeWallet.fromMnemonic(decryptedMnemonic);
        const provider = new ethers.JsonRpcProvider(
          this.networks[network].rpcUrl,
        );
        const newAccount = wallet.connect(provider);
        accountData = {
          address: newAccount.address,
          privateKey: this.encrypt(newAccount.privateKey),
        };
      } else if (network === "solana") {
        const seed = mnemonicToSeedSync(decryptedMnemonic);
        const path = `m/44'/501'/0'/0'`;
        const derivedSeed = derivePath(path, seed.toString("hex")).key;
        const keypair = nacl.sign.keyPair.fromSeed(derivedSeed);
        const account = Keypair.fromSecretKey(keypair.secretKey);
        accountData = {
          address: account.publicKey.toBase58(),
          privateKey: this.encrypt(
            Buffer.from(account.secretKey).toString("hex"),
          ),
        };
      } else {
        throw new Error("Unsupported network.");
      }

      const accountsFile = path.join(walletDir, "accounts.json");
      let accounts = {};
      try {
        const existingAccounts = await fs.readFile(accountsFile, "utf8");
        accounts = JSON.parse(existingAccounts);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }

      accounts[network] = accounts[network] || [];
      accounts[network].push(accountData);

      await fs.writeFile(accountsFile, JSON.stringify(accounts, null, 2));
      console.log(
        `Added account for wallet ${walletName} on network ${network}`,
      );
    } catch (error) {
      console.error(`Error adding account: ${error.message}`);
    }
  }

  async listWallets() {
    console.log("Your wallets:");
    try {
      const wallets = await fs.readdir(this.walletsDir);
      wallets.forEach((dir) => {
        console.log(`- ${dir}`);
      });
    } catch (error) {
      if (error.code === "ENOENT") {
        console.log("No wallets found.");
      } else {
        throw error;
      }
    }
  }

  async listAccounts(walletName) {
    const accountsFile = path.join(
      this.walletsDir,
      walletName,
      "accounts.json",
    );

    try {
      const accountsData = await fs.readFile(accountsFile, "utf8");
      const accounts = JSON.parse(accountsData);
      console.log(`Accounts for wallet ${walletName}:`);
      Object.entries(accounts).forEach(([network, networkAccounts]) => {
        console.log(`Network: ${network}`);
        networkAccounts.forEach((account, index) => {
          console.log(`  ${index + 1}. Address: ${account.address}`);
        });
      });
    } catch (error) {
      if (error.code === "ENOENT") {
        console.log(`No accounts found for wallet ${walletName}.`);
      } else {
        throw error;
      }
    }
  }

  async showPrivateKey(walletName, index, network) {
    const accountsFile = path.join(
      this.walletsDir,
      walletName,
      "accounts.json",
    );

    try {
      const accountsData = await fs.readFile(accountsFile, "utf8");
      const accounts = JSON.parse(accountsData);
      const account = accounts[network][index - 1];
      const decryptedPrivateKey = this.decrypt(account.privateKey);
      console.log(`Private Key: ${decryptedPrivateKey}`);
    } catch (error) {
      console.error(`Error showing private key: ${error.message}`);
    }
  }

  async viewBalance(walletName, index, network) {
    const accountsFile = path.join(
      this.walletsDir,
      walletName,
      "accounts.json",
    );

    try {
      const accountsData = await fs.readFile(accountsFile, "utf8");
      const accounts = JSON.parse(accountsData);
      const account = accounts[network][index - 1];

      if (network === "ethereum") {
        const provider = new ethers.JsonRpcProvider(
          this.networks[network].rpcUrl,
        );
        const balance = await provider.getBalance(account.address);
        console.log(`Balance: ${ethers.formatEther(balance)} ETH`);
      } else if (network === "solana") {
        const connection = new Connection(this.networks[network].rpcUrl);
        const balance = await connection.getBalance(
          new PublicKey(account.address),
        );
        console.log(`Balance: ${balance / LAMPORTS_PER_SOL} SOL`);
      } else {
        console.log("Unsupported network.");
      }
    } catch (error) {
      console.error(`Error viewing balance: ${error.message}`);
    }
  }

  async askQuestion(query) {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    const answer = await rl.question(query);
    rl.close();
    return answer;
  }

  async handleCLI() {
    await this.promptForPassword();

    while (true) {
      console.log(`
1. Create Wallet
2. Add Account
3. List Wallets
4. List Accounts
5. View Balance
6. Show Private Key
7. Exit`);

      const choice = await this.askQuestion("Choose an option: ");

      switch (choice) {
        case "1": {
          const walletName = await this.askQuestion("Enter wallet name: ");
          await this.createWallet(walletName);
          break;
        }
        case "2": {
          const walletName = await this.askQuestion("Enter wallet name: ");
          const network = await this.askQuestion(
            "Enter network (ethereum/solana): ",
          );
          await this.addAccount(walletName, network);
          break;
        }
        case "3": {
          await this.listWallets();
          break;
        }
        case "4": {
          const walletName = await this.askQuestion("Enter wallet name: ");
          await this.listAccounts(walletName);
          break;
        }
        case "5": {
          const walletName = await this.askQuestion("Enter wallet name: ");
          const index = await this.askQuestion("Enter account index: ");
          const network = await this.askQuestion(
            "Enter network (ethereum/solana): ",
          );
          await this.viewBalance(walletName, parseInt(index), network);
          break;
        }
        case "6": {
          const walletName = await this.askQuestion("Enter wallet name: ");
          const index = await this.askQuestion("Enter account index: ");
          const network = await this.askQuestion(
            "Enter network (ethereum/solana): ",
          );
          await this.showPrivateKey(walletName, parseInt(index), network);
          break;
        }
        case "7": {
          console.log("Not your Keys Not Your Coin!");
          process.exit(0);
        }
        default: {
          console.log("Invalid option.");
        }
      }
    }
  }
}

(async () => {
  const wallet = new MultiChainWallet();
  await wallet.initialize();
  await wallet.handleCLI();
})();
