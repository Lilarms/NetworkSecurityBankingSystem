//import defaultpackage.DESUtil;
//import finalproject.MACUtil;

import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Date;

public class EchoServer {

    private String userSymmetricKey;
    private byte[] encryptionKey;
    private byte[] macKey;
    private String macKeyHex;
    private static final String KEY_FILE_PATH = "symmetrickey.txt";
    private static DESUtil userDesUtil;
    private static MACUtil userMACUtil;
    static String mackey = "SecretKey123";
    static BankAccount userAcc = new BankAccount();

    // Method to generate a symmetric key if it doesn't exist and initialize DESUtil
    public void generateAndInitializeSymmetricKey() {
        try {
            File keyFile = new File(KEY_FILE_PATH);
            if (keyFile.exists()) {
                // If the key file already exists, read the key from it
                BufferedReader br = new BufferedReader(new FileReader(KEY_FILE_PATH));
                userSymmetricKey = br.readLine();
                br.close();
            } else {
                // Generate a new symmetric key
                Random rnd = new Random();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i++) {
                    // Append a random character to the key string
                    sb.append((char) ('A' + rnd.nextInt(26)));
                }
                userSymmetricKey = sb.toString();

                // Write the key to the file
                BufferedWriter bw = new BufferedWriter(new FileWriter(KEY_FILE_PATH));
                bw.write(userSymmetricKey);
                bw.close();
            }

            // Initialize DESUtil with the symmetric key
            userDesUtil = new DESUtil(userSymmetricKey);

            // Derive encryption and MAC keys from the master key
            deriveKeysFromMasterKey();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void AuditLog(String ID, int input, int amount, String Mac) {
        // Check if AuditLog.txt file exists, if not, create it
        long currentTimeMillis = System.currentTimeMillis();
        Date currentDate = new Date(currentTimeMillis);
        System.out.println("Current Timestamp: " + currentDate);
        try {
            File file = new File("AuditLog.txt");
            if (!file.exists()) {
                file.createNewFile();
                System.out.println("AuditLog.txt created successfully.");
            }

            // Write the audit log entry to the file
            FileWriter writer = new FileWriter(file, true);
            writer.write("ID: " + ID + ", Input: " + input + ", Amount: " + amount + ", MAC Address: " + Mac + ", Time: " + currentDate + "\n");
            writer.close();
            System.out.println("Audit log entry added to AuditLog.txt.");
        } catch (IOException e) {
            System.out.println("An error occurred while creating or writing to AuditLog.txt.");
            e.printStackTrace();
        }
    }

    // Method to derive encryption and MAC keys from the master key
    private void deriveKeysFromMasterKey() {
        try {
            // Generate a secret key from the master key using KeyGenerator
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            keyGenerator.init(56); // DES key size is 56 bits
            SecretKey secretKey = keyGenerator.generateKey();

            // Convert the secret key bytes into a byte array
            byte[] masterKeyBytes = secretKey.getEncoded();

            // Use the first half of the master key as the encryption key
            encryptionKey = Arrays.copyOfRange(masterKeyBytes, 0, masterKeyBytes.length / 2);

            // Use the second half of the master key as the MAC key
            macKey = Arrays.copyOfRange(masterKeyBytes, masterKeyBytes.length / 2, masterKeyBytes.length);

            // Convert the MAC key to hexadecimal string
            macKeyHex = bytesToHex(macKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // Helper method to convert bytes to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    // Static method to print the keys
    public static void printKeys(EchoServer server) {
        System.out.println("Master Key: " + server.userSymmetricKey);
        System.out.println("Encryption Key: " + bytesToHex(server.encryptionKey));
        System.out.println("MAC Key: " + server.macKeyHex);

    }

    public static void main(String[] args) throws IOException {
        int portNumber = 1234;

        // Define the expected username and password
        String expectedUsername = "Armin123";
        String expectedPassword = "Yeet";

        // Create an instance of EchoServer
        EchoServer server = new EchoServer();

        // Generate and initialize the symmetric key
        server.generateAndInitializeSymmetricKey();

        try (
                ServerSocket serverSocket = new ServerSocket(1234); Socket clientSocket = serverSocket.accept(); PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));) {

            // ********************* Part 1 *********************
            // Read the username from the client and decrypt it
            System.out.println("Loading Client Username...");
            boolean logging_in = true;
            while (logging_in) {
                // Read the username from the client and decrypt it
                System.out.println("Loading Client Username...");
                String encryptedUsername = in.readLine();
                String receivedUsername = server.userDesUtil.decrypt(encryptedUsername);
                System.out.println("Received username from client (encrypted) " + encryptedUsername);
                System.out.println("Received username from client (decrypted):  " + receivedUsername);

                // Read the password from the client and decrypt it
                System.out.println("Loading Client Password...");
                String encryptedPassword = in.readLine();
                String receivedPassword = server.userDesUtil.decrypt(encryptedPassword);
                System.out.println("Received password from client (encrypted) " + encryptedPassword);
                System.out.println("Received password from client (decrypted): " + receivedPassword);

                // Check if the received username and password match the expected values
                if (receivedUsername.equals(expectedUsername) && receivedPassword.equals(expectedPassword)) {
                    // Send a confirmation message indicating successful login
                    out.println("LOGIN_SUCCESSFUL");
                    logging_in = false;
                } else {
                    // Send a message indicating incorrect username or password
                    out.println("LOGIN_FAILED");
                }
            }

            // ********************* Part 2 *********************
            // Receive Message 1
            String msg1Encrypt = in.readLine();
            String DecryptedMsg1 = userDesUtil.decrypt(msg1Encrypt);
            System.out.println("Receive Message 1: " + DecryptedMsg1);
            String identityA = DecryptedMsg1.split(",")[0];
            String nonceA = DecryptedMsg1.split(",")[1];

            // Encrypt Message 2
            String identityB = "IDServer";
            Random random = new Random();
            int randomNumber = random.nextInt(500) + 1;
            String nonceB = String.valueOf(randomNumber);
            String msg2 = nonceB + "," + userDesUtil.encrypt(identityB + "," + nonceA);

            // Send Message 2
            out.println(msg2);

            // Receive Message 3
            String msg3 = in.readLine();
            System.out.println("Receive Message 3: " + msg3);

            // Decrypt Message 3
            String msg3decrypted = userDesUtil.decrypt(msg3);
            System.out.println("Decrypt Message 3: " + msg3decrypted);
            String recievedNonce = msg3decrypted.split(",")[1];
            System.out.println("sent nonce: " + nonceB);
            System.out.println("recieved nonce: " + recievedNonce);
            if (nonceB.equals(recievedNonce)) {
                System.out.println("Server Verified!");
            } else {
                System.out.println("Nonces do not match, Server cannot be verified");
            }
            // ********************* Part 3 *********************
            // Print the keys
            printKeys(server);
            out.println(server.userSymmetricKey);
            out.println(bytesToHex(server.encryptionKey));
            out.println(server.macKeyHex);
            // ********************* Part 4 *********************

//            // Receive Message and Key
//            String message = in.readLine();
//            String mac = in.readLine();
//            System.out.println(message);
//            System.out.println(mac);
//            boolean isVerified = userMACUtil.decrypt(message, mackey, mac);
//            System.out.println("Message integrity verified: " + isVerified);
//
//            System.out.println(userAcc.balance());
//            System.out.println(userAcc.withdrawal(200));
//            System.out.println(userAcc.balance());
//            userAcc.deposit(100);
//            System.out.println(userAcc.balance());
            //System.out.println(function_choice);
// Process the function choice using a switch statement
            String function_choice = in.readLine();
            switch (function_choice) {
                case "1":
                    out.println("Deposit!");
                    out.println("How much would you like to deposit?");
                    //String amount_deposit_str = in.readLine();
                    String amount_deposit_str = (in.readLine());
                    String mac = in.readLine();
                    String decrypted_amount = userDesUtil.decrypt(amount_deposit_str);
                    System.out.println("Encrypted amount to deposit " + amount_deposit_str);
                    System.out.println("Decrypted amount to deposit " + decrypted_amount);
                    int amount_deposit = Integer.parseInt(decrypted_amount);
                    System.out.println(amount_deposit + " Deposited");
                    userAcc.deposit(amount_deposit);
                    boolean mac_decrypted = MACUtil.decrypt(amount_deposit_str, "TMU", mac);
                    System.out.println("MAC successful: " + mac_decrypted);

                    if (mac_decrypted == true) {
                        AuditLog(identityA, 1, amount_deposit, mac);
                    }

                    break;
                case "2":
                    out.println("Withdrawal!");
                    out.println("How much would you like to withdraw?");
                    String amount_withdrawn_str = (in.readLine());
                    String mac1 = in.readLine();
                    String amount_withdraw_decrypt = userDesUtil.decrypt(amount_withdrawn_str);
                    System.out.println("Encrypted amount to Withdraw " + amount_withdrawn_str);
                    System.out.println("Decrypted amount to withdraw " + amount_withdraw_decrypt);
                    int amount_withdrawn = Integer.parseInt(amount_withdraw_decrypt);
                    System.out.println(amount_withdrawn + " Withdrawn");
                    userAcc.withdrawal(amount_withdrawn);
                    boolean mac_decrypted1 = MACUtil.decrypt(amount_withdrawn_str, "TMU", mac1);
                    System.out.println("Mac successful: " + mac_decrypted1);

                    if (mac_decrypted1 == true) {
                        AuditLog(identityA, 2, amount_withdrawn, mac1);
                    }

                    break;
                case "3":
                    out.println("View Balance!");
                    out.println(userAcc.balance());
                    AuditLog(identityA, 3, userAcc.balance(), null);
                    
                    break;
                default:
                    // Default case: Invalid function choice
                    System.out.println("Invalid function choice");
            }

        } catch (IOException e) {
            System.out.println("Exception caught when trying to listen on port " + portNumber + " or listening for a connection");
            System.out.println(e.getMessage());
        }
    }
}
