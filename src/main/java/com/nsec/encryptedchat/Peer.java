package com.nsec.encryptedchat;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Peer {

    private static final int PORT = 12345;
    private static PublicKey peerPublicKey;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static SecretKey aesKey;
    private static boolean isInitiator = false;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Are you initiating the connection? (yes/no): ");
        isInitiator = scanner.nextLine().equalsIgnoreCase("yes");

        // Generate RSA key pair
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair keyPair = rsaGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        if (isInitiator) {
            System.out.print("Enter peer IP address: ");
            String ip = scanner.nextLine();
            initiateConnection(ip);
        } else {
            waitForConnection();
        }

        // Chat loop
        while (true) {
            System.out.print("You: ");
            String message = scanner.nextLine();
            String encryptedMessage = encryptAES(message);
            sendMessage(encryptedMessage);
        }
    }

    // === P2P Connection Methods ===

    private static Socket socket;
    private static DataInputStream in;
    private static DataOutputStream out;

    private static void initiateConnection(String ip) throws Exception {
        socket = new Socket(ip, PORT);
        initStreams();

        // Step 1: Send our public key
        sendBase64(publicKey.getEncoded());

        // Step 2: Receive peer's public key
        peerPublicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(receiveBase64())
        );

        // Step 3: Generate AES key and send it encrypted
        aesKey = generateAESKey();
        byte[] encryptedAESKey = encryptRSA(aesKey.getEncoded(), peerPublicKey);
        sendBase64(encryptedAESKey);

        // Start receiver thread
        new Thread(Peer::receiveLoop).start();
    }

    private static void waitForConnection() throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Waiting for connection on port " + PORT + "...");
        socket = serverSocket.accept();
        initStreams();

        // Step 1: Receive peer's public key
        peerPublicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(receiveBase64())
        );

        // Step 2: Send our public key
        sendBase64(publicKey.getEncoded());

        // Step 3: Receive and decrypt AES key
        byte[] encryptedAESKey = receiveBase64();
        byte[] aesKeyBytes = decryptRSA(encryptedAESKey, privateKey);
        aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Start receiver thread
        new Thread(Peer::receiveLoop).start();
    }

    private static void initStreams() throws IOException {
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());
    }

    // === Secure Messaging ===

    private static void receiveLoop() {
        try {
            while (true) {
                String encryptedMessage = in.readUTF();
                String decryptedMessage = decryptAES(encryptedMessage);
                System.out.println("\nPeer: " + decryptedMessage);
                System.out.print("You: ");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendMessage(String message) throws IOException {
        out.writeUTF(message);
        out.flush();
    }

    // === Encryption Helpers ===

    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        return gen.generateKey();
    }

    private static String encryptAES(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decryptAES(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }

    private static byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] decryptRSA(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static void sendBase64(byte[] data) throws IOException {
        out.writeUTF(Base64.getEncoder().encodeToString(data));
        out.flush();
    }

    private static byte[] receiveBase64() throws IOException {
        return Base64.getDecoder().decode(in.readUTF());
    }
}
