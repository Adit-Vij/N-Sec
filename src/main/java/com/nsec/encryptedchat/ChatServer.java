package com.nsec.encryptedchat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class ChatServer {
    private static final int PORT = 1010;
    private static SecretKey aesKey;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public static void handleConnection() {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            Socket clientSocket = serverSocket.accept();

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            out.writeObject(publicKey);
            out.flush();

            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
            String encryptedAESKey = (String) in.readObject();

            aesKey = decryptAESKey(encryptedAESKey, privateKey);

            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

            String message;
            while ((message = reader.readLine()) != null) {
                String decryptedMessage = CryptoUtils.decryptAES(message, aesKey);
                writer.println(message);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        return CryptoUtils.bytesToAESKey(decryptedKeyBytes);
    }
}
