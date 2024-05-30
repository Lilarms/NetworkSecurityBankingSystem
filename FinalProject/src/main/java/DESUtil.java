
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DESUtil {

    private final String ALGO = "DES";
    private final String MODE = "ECB";
    private final String PADDING_SCHEME = "PKCS5Padding";
    private Key key;
    String transformation;

    byte[] ivBytes;

    public DESUtil(String key){
        //DES/ECB/NoPadding
        this.key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGO);
        transformation = String.format("%s/%s/%s", ALGO, MODE, PADDING_SCHEME);
    }

    public String encrypt(String valueToEncrypt) {
        Cipher instance = null;
        try {
            instance = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

        try {
            instance.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        byte[] bytes = new byte[0];

        try {
            bytes = instance.doFinal(valueToEncrypt.getBytes());
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    public String decrypt(String encryptedValue) {
        Cipher instance = null;
        try {
            instance = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }

        try {
            instance.init(Cipher.DECRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        byte[] bytes = new byte[0];
        try {
            bytes = instance.doFinal(Base64.getDecoder().decode(encryptedValue));
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return new String(bytes);
    }

    public static void main(String[] args) throws IOException {
//        String text = "hello world";
//
//        DESUtil2 desUtil = new DESUtil2("12345678");
//        String encryptedValue = desUtil.encrypt(text);
//        System.out.println(encryptedValue);
//
//        String decryptedValue = desUtil.decrypt(encryptedValue);
//        System.out.println(decryptedValue);


    }
}
