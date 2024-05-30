import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {
    public final int keySizeSmall = 162;
    public final int keySizeLarge = 294;

    public KeyPairGenerator generator;
    public KeyPair pairSmall, pairLarge;
    public PrivateKey privateKeySmall, privateKeyLarge;
    public PublicKey publicKeySmall, publicKeyLarge;
    public PublicKey otherPublicKeySmall, otherPublicKeyLarge;

    public RSA(){       generateKeyPair();

    }

    private void generateKeyPair(){
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        generator.initialize(1028);
        pairSmall = generator.generateKeyPair();
        privateKeySmall = pairSmall.getPrivate();
        publicKeySmall = pairSmall.getPublic();

        generator.initialize(2048);
        pairLarge = generator.generateKeyPair();
        privateKeyLarge = pairLarge.getPrivate();
        publicKeyLarge = pairLarge.getPublic();
    }

    public String getPublicKey(String size){
        // Get the public key
        PublicKey publicKey = null;
        if(size.equals("small")){
            publicKey = pairSmall.getPublic();
        } else if (size.equals("large")) {
            publicKey = pairLarge.getPublic();
        }

        // Convert the public key to a byte array
        byte[] publicKeyBytes = publicKey.getEncoded();

        // Convert the byte array to a Base64-encoded string (for easier transmission)
        return Base64.getEncoder().encodeToString(publicKeyBytes);
    }
    public void setOtherPublicKey(String receivedPublicKeyString) {
        byte[] receivedPublicKeyBytes = Base64.getDecoder().decode(receivedPublicKeyString);

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(receivedPublicKeyBytes);
        try {
            if (receivedPublicKeyBytes.length == keySizeSmall){
                otherPublicKeySmall = keyFactory.generatePublic(publicKeySpec);
            } else if (receivedPublicKeyBytes.length == keySizeLarge) {
                otherPublicKeyLarge = keyFactory.generatePublic(publicKeySpec);
            }

        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
    public String encrypt(String valueToEncrypt, String mode, String size){

        Cipher encryptCipher = null;
        try {
            encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        try {
            if (mode.equals("other")){
                if (size.equals("small")){
                    encryptCipher.init(Cipher.ENCRYPT_MODE, otherPublicKeySmall);
                } else if (size.equals("large")) {
                    encryptCipher.init(Cipher.ENCRYPT_MODE, otherPublicKeyLarge);
                }

            } else if (mode.equals("self")){
                if (size.equals("small")){
                    encryptCipher.init(Cipher.ENCRYPT_MODE, privateKeySmall);
                } else if (size.equals("large")) {
                    encryptCipher.init(Cipher.ENCRYPT_MODE, privateKeyLarge);
                }
            }
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        byte[] secretMessageBytes = valueToEncrypt.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = new byte[0];
        try {
            encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }


    public String decrypt(String encryptedValue, String mode, String size){
        byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedValue);

        Cipher decryptCipher = null;
        try {
            decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        try {
            if (mode.equals("other")){
                if (size.equals("small")){
                    decryptCipher.init(Cipher.DECRYPT_MODE, otherPublicKeySmall);
                } else if (size.equals("large")) {
                    decryptCipher.init(Cipher.DECRYPT_MODE, otherPublicKeyLarge);
                }

            } else if (mode.equals("self")){
                if (size.equals("small")){
                    decryptCipher.init(Cipher.DECRYPT_MODE, privateKeySmall);
                } else if (size.equals("large")) {
                    decryptCipher.init(Cipher.DECRYPT_MODE, privateKeyLarge);
                }
            }

        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        byte[] decryptedMessageBytes = new byte[0];
        try {
            decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
//        RSA rsa1 = new RSA();
//        RSA rsa2 = new RSA();
//
//        String publicKeySmallA = rsa1.getPublicKey("small");
//        rsa2.setOtherPublicKey(publicKeySmallA);
//        String publicKeySmallB = rsa2.getPublicKey("small");
//        rsa1.setOtherPublicKey(publicKeySmallB);
//        String publicKeyLargeA = rsa1.getPublicKey("large");
//        rsa2.setOtherPublicKey(publicKeyLargeA);
//        String publicKeyLargeB = rsa2.getPublicKey("large");
//        rsa1.setOtherPublicKey(publicKeyLargeB);
//
//
//        String msg = "secret message";
//        System.out.println(msg);
//
//        String encryptedMsg = rsa2.encrypt(rsa2.encrypt(msg, "self", "small"), "other", "large");
//        System.out.println(encryptedMsg);
//
//        String decryptedMsg = rsa1.decrypt(rsa1.decrypt(encryptedMsg, "self", "large"), "other", "small");
//        System.out.println(decryptedMsg);


    }
}
