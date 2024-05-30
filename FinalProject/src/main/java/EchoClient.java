//import finalproject.DESUtil;
//import finalproject.MACUtil;

import java.io.*;
import java.net.*;
import java.util.Random;
import java.util.Scanner;

public class EchoClient {

    private static final String KEY_FILE_PATH = "symmetrickey.txt";
    private static DESUtil userDesUtil;
    private static MACUtil userMACUtil;
    static public String mackey = "SecretKey123";

    public static void generateAndInitializeSymmetricKey() {
        try {
            File keyFile = new File(KEY_FILE_PATH);
            if (keyFile.exists()) {
                // If the key file already exists, read the key from it
                BufferedReader br = new BufferedReader(new FileReader(KEY_FILE_PATH));
                String userSymmetricKey = br.readLine();
                br.close();

                // Initialize DESUtil with the symmetric key
                userDesUtil = new DESUtil(userSymmetricKey);
            } else {
                System.out.println("Symmetric key file not found.");
                System.exit(1);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {
        String hostName = "localhost";
        int portNumber = 1234;

        generateAndInitializeSymmetricKey();

        try (
                Socket echoSocket = new Socket(hostName, portNumber); PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true); BufferedReader in = new BufferedReader(new InputStreamReader(echoSocket.getInputStream())); BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));) {
            Scanner scanner = new Scanner(System.in);

            // ********************* Part 1 *********************
            boolean logging_in = true;
            while (logging_in) {// Prompt the user for username and password
                // Prompt the user for username and password
                System.out.println("Enter Username:");
                String username = scanner.nextLine();
                System.out.println("Enter Password:");
                String password = scanner.nextLine();

                // Encrypt the username and password using the shared session key
                String encryptedUsername = userDesUtil.encrypt(username);
                String encryptedPassword = userDesUtil.encrypt(password);

                // Send the encrypted username and password to the server
                out.println(encryptedUsername);
                out.println(encryptedPassword);

                // Receive and print the server's response
                String response = in.readLine();
                System.out.println("Server Response: " + response);
                if (response.equals("LOGIN_SUCCESSFUL")) {
                    logging_in = false;
                }
            }

            // ********************* Part 2 *********************
            // Send Message 1
            Random random = new Random();
            int randomNumber = random.nextInt(500) + 1;
            String identityA = "IDClient";
            String nonceA = String.valueOf(randomNumber);
            String msg1 = identityA + "," + nonceA;
            String msg1Encrypted = userDesUtil.encrypt(msg1);
            System.out.println("client's msg1: " + msg1);
            out.println(msg1Encrypted);

            // Receive Message 2
            String msg2 = in.readLine();
            System.out.println("Receive Message 2: " + msg2);

            // Decrypt Message 2
            String nonceB = msg2.split(",")[0];
            String msg2encrypted = msg2.split(",")[1];
            String msg2decrypted = userDesUtil.decrypt(msg2encrypted);
            System.out.println("Decrypt Message 2 : " + msg2decrypted);

            // Encrypt Message 3
            String msg3 = userDesUtil.encrypt(identityA + "," + nonceB);

            // Send Message 3
            out.println(msg3);

            String recievedNonce = msg2decrypted.split(",")[1];
            System.out.println("sent nonce: " + nonceA);
            System.out.println("recieved nonce: " + recievedNonce);
            if (nonceA.equals(recievedNonce)) {
                System.out.println("Client Verified!");
            } else {
                System.out.println("Nonces do not match, Server cannot be verified");
            }
            // ********************* Part 3 *********************
            String userSymmetricKey = in.readLine();
            String encryptionKey = in.readLine();
            String macKey = in.readLine();

            // Send Mac
//            String message = "Hello, world!";
//            String mac = userMACUtil.encrypt(message, mackey);
//            out.println(message);
//            out.println(mac);
            // ********************* Part 4 *********************
            System.out.println("Please enter which function you would like to do");
            String scanx = scanner.nextLine();
            out.println(scanx);

            String response_for_choice = in.readLine();
            String response_for_choice1 = in.readLine();
            System.out.println(response_for_choice);

            switch (response_for_choice) {
                case "Deposit!":
                    System.out.println("How much would you like to deposit?");
                    String deposit_amount = scanner.nextLine();
                    String encrypted_deposit_amount = userDesUtil.encrypt(deposit_amount);
                    System.out.println("Encrypted Amount Sent " + encrypted_deposit_amount);
                    System.out.println("Decrypted Amount Sent " + userDesUtil.decrypt(encrypted_deposit_amount));
                    String mac = MACUtil.encrypt(encrypted_deposit_amount, "TMU");
                    out.println(encrypted_deposit_amount);
                    out.println(mac);
                    break;
                case "Withdrawal!":
                    System.out.println("How much would you like to withdraw?");
                    String withdrawal_amount = scanner.nextLine();
                    String encrypted_withdrawal_amount = userDesUtil.encrypt(withdrawal_amount);
                    System.out.println("Encrypted amount to withdraw " + encrypted_withdrawal_amount);
                    System.out.println("Decrytped amount to withdraw " + withdrawal_amount);
                    String mac1 = MACUtil.encrypt(encrypted_withdrawal_amount, "TMU");
                    out.println(encrypted_withdrawal_amount);
                    out.println(mac1);
                    break;
                case "View Balance!":
                    System.out.println(response_for_choice1);
                    break;
                default:
                    // Default case: Invalid function choice
                    System.out.println("Invalid function choice");
            }

        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " + hostName);
            System.exit(1);
        }
    }
}
