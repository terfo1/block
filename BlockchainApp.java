import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

class Transaction {
    public String sender;
    public String recipient;
    public double amount;
    public long timestamp;
    public String signature;

    public Transaction(String sender, String recipient, double amount) {
        this.sender = sender;
        this.recipient = recipient;
        this.amount = amount;
        this.timestamp = System.currentTimeMillis();
    }

    public String hash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(String.format(
                            "%s%s%f%d", sender, recipient, amount, timestamp)
                    .getBytes(StandardCharsets.UTF_8));

            StringBuilder hashHex = new StringBuilder();
            for (byte b : hashBytes) {
                hashHex.append(String.format("%02x", b));
            }

            return hashHex.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void sign(PrivateKey privateKey) {
        try {
            Signature signatureAlgorithm = Signature.getInstance("SHA256withRSA");
            signatureAlgorithm.initSign(privateKey);
            signatureAlgorithm.update(hash().getBytes());
            this.signature = Base64.getEncoder().encodeToString(signatureAlgorithm.sign());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class Block {
    public String prevHash;
    public List<Transaction> transactions = new ArrayList<>();
    public long timestamp;
    public String hash;

    public Block(String prevHash) {
        this.prevHash = prevHash;
        this.timestamp = System.currentTimeMillis();
        this.hash = calculateHash();
    }

    public String calculateHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String blockData = prevHash + transactions.toString() + timestamp;
            byte[] hashBytes = digest.digest(blockData.getBytes(StandardCharsets.UTF_8));

            StringBuilder hashHex = new StringBuilder();
            for (byte b : hashBytes) {
                hashHex.append(String.format("%02x", b));
            }

            return hashHex.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void addTransaction(Transaction transaction, PublicKey publicKey) {
        try {
            Signature signatureAlgorithm = Signature.getInstance("SHA256withRSA");
            signatureAlgorithm.initVerify(publicKey);
            signatureAlgorithm.update(transaction.hash().getBytes());

            if (signatureAlgorithm.verify(Base64.getDecoder().decode(transaction.signature))) {
                transactions.add(transaction);
                this.hash = calculateHash();
                System.out.println("Transaction added successfully.");
            } else {
                System.out.println("Invalid signature. Transaction rejected.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class Blockchain {
    private List<Block> chain = new ArrayList<>();

    public Blockchain() {
        chain.add(createGenesisBlock());
    }

    private Block createGenesisBlock() {
        return new Block("0");
    }

    public Block getLatestBlock() {
        return chain.get(chain.size() - 1);
    }

    public void addBlock(Block block) {
        block.prevHash = getLatestBlock().hash;
        block.hash = block.calculateHash();
        chain.add(block);
    }
}

public class BlockchainApp {
    public static void main(String[] args) {
        Blockchain blockchain = new Blockchain();
        KeyPair keyPair = generateKeyPair();

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter recipient address: ");
        String recipient = scanner.nextLine();

        System.out.print("Enter transaction amount: ");
        double amount = scanner.nextDouble();

        Transaction transaction = new Transaction(keyPair.getPublic().toString(), recipient, amount);
        transaction.sign(keyPair.getPrivate());

        Block block = new Block(blockchain.getLatestBlock().hash);
        block.addTransaction(transaction, keyPair.getPublic());

        blockchain.addBlock(block);

        System.out.println("Blockchain after adding a block:");
        System.out.println(blockchain.getLatestBlock().hash);
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
