import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class DES {
	static Cipher cipher;
	
	/**
	 * constructor
	 * @throws Exception
	 */
	public DES() throws Exception {
		cipher = Cipher.getInstance("DES");
		
	}

	/**
	 * takes in plain text and a key. converts the plain text into an array of itself in byte format. Then initialises cipher into encryption mode using key.
	 * the encryption is performed and returns the cipher text in byte format.
	 * encoder is then used to convert the bytes back to text.
	 * @param plainText
	 * @param secretKey
	 * @return cipher text
	 * @throws Exception
	 */
	public static String encrypt(String plainText, SecretKey secretKey) throws Exception {
		
		//Convert plaintext into byte representation
		byte[] plainTextByte = plainText.getBytes();
		
		//Initialise the cipher to be in encrypt mode, using the given key.
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
		//Perform the encryption
		byte[] encryptedByte = cipher.doFinal(plainTextByte);
		
		//Get a new Base64 (ASCII) encoder and use it to convert ciphertext back to a string
		Base64.Encoder encoder = Base64.getEncoder();
		String encryptedText = encoder.encodeToString(encryptedByte);
		
		return encryptedText;
	}

	/**
	 * This method takes in the encrypted text in string form and the secret key, converts the text to bytes, initialises the cipher into decrypt mode using the secret key
	 * executes the decryption which returns the plain text in byte format, the bytes are then converted to strings.
	 * @param encryptedText
	 * @param secretKey
	 * @return decrypted text
	 * @throws Exception
	 */
	public String decrypt(String encryptedText, SecretKey secretKey)
			throws Exception {
		//Get a new Base64 (ASCII) decoder and use it to convert ciphertext from a string into bytes
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] encryptedTextByte = decoder.decode(encryptedText);
		
		//Initialise the cipher to be in decryption mode, using the given key.
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		
		//Perform the decryption
		byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
		
		//Convert byte representation of plaintext into a string
		String decryptedText = new String(decryptedByte);
		
		return decryptedText;
	}
	
	
	/**
	 * calls getInstance method of KEyGenerator class, this looks for security providers that match the 
	 * input string and then return a KeyGenerator object that will supports that provider. the key object is then initialised to 128 bytes in size
	 * a secret key is then generated, this is then converted from SecretKey obj to a string and returned
	 * @return secret key
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKey generateRandomKey() throws NoSuchAlgorithmException{
		//Use java's key generator to produce a random key.
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey secretKey = keyGenerator.generateKey();
		
		//print the key
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		System.out.println(encodedKey);

		return secretKey;
	}
	
	/**
	 * the string password input is converted to bytes, a Message digest obj is then initialised with specific implemenation of algorithm:
	 *  SHA-1, the digest method then performs the hash computation adding padding if nesecary and returns the key as array of bytes
	 *  the parabits are then removed from the array to aquire just the key, secret key is then computed from the hash key for the algorithm specified
	 *  secret key is then converted from SecretKeySpec obj to string and printed out.
	 * 
	 * @param password
	 * @return secret key
	 * @throws Exception
	 */
	public SecretKey generateKeyFromPassword(String password) throws Exception{
	
		//Get byte representation of password.
		//Note here you should ideally also use salt!
		byte[] passwordInBytes = (password).getBytes("UTF-8");
		
		//Use sha to generate a message digest of the password
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		byte[] key = sha.digest(passwordInBytes);
		
		//AES keys are only 128bits (16 bytes) so take first 128 bits of digest.		
		key = Arrays.copyOf(key, 16); 

		//Generate secret key using
		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		
		//print the key
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		System.out.println(encodedKey);
		
		return secretKey;
	}
	
}