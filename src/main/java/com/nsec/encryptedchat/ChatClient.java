package com.nsec.encryptedchat;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient {
    private static final String SERVER_IP = "2.57.19.140"; // ChatServer
    private static final int SERVER_PORT = 1010;

    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private Scanner scanner;
    private String myIP, friendIP;
    private SecretKey aesKey;
    private KeyPair keyPair;

    public ChatClient() {
        scanner = new Scanner(System.in);
        connectToServer();

        System.out.print("Enter destination IP: ");
        friendIP = scanner.nextLine();

        System.out.print("Set your friendly name: ");
        String friendlyName = scanner.nextLine();

        writer.println("INVITE:" + friendIP + ":" + friendlyName);

        new Thread(this::listenForMessages).start();
        waitForAcceptance();
    }

    private void connectToServer() {
        try {
            socket = new Socket(SERVER_IP, SERVER_PORT);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(socket.getOutputStream(), true);
            myIP = socket.getLocalAddress().getHostAddress();
            System.out.println("✅ Connected to server as " + myIP);
        } catch (IOException e) {
            System.out.println("❌ Failed to connect to server.");
            System.exit(1);
        }
    }

    private void waitForAcceptance() {
        while (true) {
            try {
                String response = reader.readLine();
                if (response.startsWith("INVITE_FROM:")) {
                    String[] parts = response.split(":");
                    String inviterIP = parts[1];
                    String inviterName = parts[2];

                    System.out.println("📩 " + inviterName + " (" + inviterIP + ") wants to chat. Accept? (yes/no)");
                    String answer = scanner.nextLine();

                    if (answer.equalsIgnoreCase("yes")) {
                        writer.println("ACCEPTED:" + inviterIP);
                        friendIP = inviterIP;
                        generateKeys();

                        String encodedPublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
                        writer.println("PUBLIC_KEY:" + friendIP + ":" + encodedPublicKey);

                        System.out.println("🔑 Keys generated. Waiting for secure AES key exchange...");
                        break;
                    }
                } else if (response.startsWith("ACCEPTED_FROM:")) {
                    generateKeys();
                    System.out.println("🔑 Keys generated. Sending AES key securely...");

                    String recipientPublicKey = reader.readLine();
                    PublicKey friendPublicKey = decodePublicKey(recipientPublicKey);

                    String encryptedAESKey = encryptRSA(Base64.getEncoder().encodeToString(aesKey.getEncoded()), friendPublicKey);
                    writer.println("AES_KEY:" + friendIP + ":" + encryptedAESKey);

                    System.out.println("✅ AES key securely shared. Chat started!");
                    startChat();
                    break;
                } else if (response.startsWith("PUBLIC_KEY:")) {
                    String[] parts = response.split(":");
                    if (parts.length < 3) continue;

                    String senderIP = parts[1];
                    String encodedPublicKey = parts[2];

                    if (senderIP.equals(friendIP)) {
                        PublicKey friendPublicKey = decodePublicKey(encodedPublicKey);

                        String encryptedAESKey = encryptRSA(Base64.getEncoder().encodeToString(aesKey.getEncoded()), friendPublicKey);
                        writer.println("AES_KEY:" + friendIP + ":" + encryptedAESKey);
                    }
                } else if (response.startsWith("AES_KEY:")) {
                    String[] parts = response.split(":");
                    if (parts.length < 3) continue;

                    String senderIP = parts[1];
                    String encryptedAESKey = parts[2];

                    if (senderIP.equals(friendIP)) {
                        String decryptedAESKey = decryptRSA(encryptedAESKey);
                        aesKey = new SecretKeySpec(Base64.getDecoder().decode(decryptedAESKey), "AES");

                        System.out.println("✅ AES key received. Chat started!");
                        startChat();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void generateKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            keyPair = keyGen.generateKeyPair();

            KeyGenerator aesGen = KeyGenerator.getInstance("AES");
            aesGen.init(128);
            aesKey = aesGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void startChat() {
        while (true) {
            System.out.print("You: ");
            String message = scanner.nextLine();

            try {
                String encryptedMessage = encryptAES(message);
                writer.println("MSG:" + friendIP + ":" + encryptedMessage);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void listenForMessages() {
        try {
            while (true) {
                String incoming = reader.readLine();
                if (incoming.startsWith("MSG:")) {
                    String[] parts = incoming.split(":", 3);
                    String senderIP = parts[1];
                    String encryptedMessage = parts[2];

                    try {
                        String decryptedMessage = decryptAES(encryptedMessage);
                        System.out.println("📩 " + senderIP + ": " + decryptedMessage);
                    } catch (Exception e) {
                        System.out.println("❌ Failed to decrypt message.");
                        e.printStackTrace();
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String encryptAES(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }

    private String decryptAES(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)));
    }

    private String encryptRSA(String data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }

    private String decryptRSA(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)));
    }

    private PublicKey decodePublicKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes)); 
    }

    // public static void main(String[] args) {
    //     new ChatClient();
    // }
}
    