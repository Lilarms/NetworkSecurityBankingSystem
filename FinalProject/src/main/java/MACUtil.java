

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MACUtil {
    private static final String ALGORITHM = "HmacSHA256";

    public static String encrypt(String message, String key) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            mac.init(secretKey);
            byte[] macBytes = mac.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(macBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean decrypt(String message, String key, String expectedMac) {
        String calculatedMac = encrypt(message, key);
        return calculatedMac != null && calculatedMac.equals(expectedMac);
    }

    public static void main(String[] args) {
        String key = "SecretKey123";
        String message = "Hello, world!";

        String mac = encrypt(message, key);
        System.out.println("MAC: " + mac);

        // Assuming you're sending the message and MAC over the network
        // and then verifying the integrity of the message
        boolean isVerified = decrypt(message, key, mac);
        System.out.println("Message integrity verified: " + isVerified);
    }
}
