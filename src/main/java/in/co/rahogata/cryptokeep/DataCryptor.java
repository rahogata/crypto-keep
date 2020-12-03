/**
 * 
 */
package in.co.rahogata.cryptokeep;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author shiva
 *
 */
class DataCryptor{

    private static final String KEY_ALGO = "PBKDF2WithHmacSHA256";
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_BIT = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final String AES = "AES";
    private static final int SALT_LENGTH_BYTE = 16;
    
    public String encrypt(char[] key, String content) throws DataCryptException {
        try {
            byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
            SecretKey secretKey = getAESKey(key, salt);
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] cipherTxt = cipher.doFinal(content.getBytes(UTF_8));
            byte[] result = ByteBuffer.allocate(iv.length + salt.length + cipherTxt.length)
                            .put(iv).put(salt).put(cipherTxt).array();
            return getEncoder().encodeToString(result);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new DataCryptException(e);
        }
    }

    public String decrypt(char[] key, String content) throws DataCryptException {
        try {
            byte[] decoded = getDecoder().decode(content.getBytes(UTF_8));
            ByteBuffer encryptedBuffer = ByteBuffer.wrap(decoded);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            encryptedBuffer.get(iv);
            
            byte[] salt = new byte[SALT_LENGTH_BYTE];
            encryptedBuffer.get(salt);
            
            byte[] cipherTxt = new byte[encryptedBuffer.remaining()];
            encryptedBuffer.get(cipherTxt);
            
            SecretKey secretKey = getAESKey(key, salt);
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] result = cipher.doFinal(cipherTxt);
            return new String(result, UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            throw new DataCryptException(e);
        }
        
    }

    private byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private SecretKey getAESKey(char[] password, byte[] salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGO);
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, AES_KEY_BIT);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES);
    }
}
