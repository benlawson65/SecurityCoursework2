
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import java.util.Base64;
import java.io.FileWriter;
import java.io.PrintWriter;

public class PuzzleGenerationAndEncryption {

	public static void main(String args[]) throws Exception{
		//create zero byte padding at the beginning
		byte[] zeroBytes = new byte[16];
		
		ArrayList<String> puzzleEncrypted = new ArrayList<String>();
		ByteArrayOutputStream byteToStringStream = new ByteArrayOutputStream();
		
		//encrypt each puzzle
		for(int i = 0; i < 1024; i++){
			
			//create random puzzle number
			byte[] puzzleNumberBytes = new byte[2];
			new Random().nextBytes(puzzleNumberBytes);
			
			//create random puzzle key
			SecretKey puzzleKey = generateRandomKey();
			byte[] keyBytes = new byte[8];
			keyBytes = puzzleKey.getEncoded();
			
			byte[] padding = new byte[6];
			//form whole puzzle together
			byteToStringStream.write(zeroBytes);
			byteToStringStream.write(puzzleNumberBytes);
			byteToStringStream.write(keyBytes);
			//byteToStringStream.write(padding);
			byte wholePuzzle[] = byteToStringStream.toByteArray();
			byteToStringStream.reset();
			
			//String puzzleStr = zeroBytesStr + keyBytesStr + puzzleBytesStr;
			System.out.println(wholePuzzle.length + "unencrypted: " + CryptoLib.byteArrayToString(wholePuzzle));
			//set up encrypter and key
			SecretKey desKey = generateRandomKey();
			byte[] randomBytes = new byte[8];
			byte[] desBytes = new byte[8];
			byte[] desBytes2 = new byte[8];
			
			
			desBytes = desKey.getEncoded();	
			
			Arrays.fill(desBytes, 2, 8, (byte)0);
			System.out.println("key before des hash " + CryptoLib.byteArrayToString(desBytes) + desBytes.length);
			SecretKey desKey2 = CryptoLib.createKey(desBytes);
			
			//Arrays.fill(desBytes, 2, 8, (byte)0);
			//System.out.println(DES.encrypt(CryptoLib.byteArrayToString(wholePuzzle), desKey2).length());
			Cipher encryptionCipher = Cipher.getInstance("DES");
			encryptionCipher.init(Cipher.ENCRYPT_MODE, desKey2);
			
			//convert to UTF for encryption
			//byte[] puzzleInUTF8 = puzzleStr.getBytes("UTF8");
			byte[] encryptPuzzle = encryptionCipher.doFinal(wholePuzzle);
			
			//encode encrypted puzzle and add to array
			puzzleEncrypted.add(CryptoLib.byteArrayToString(encryptPuzzle));
			
			
			String desKeyStr = CryptoLib.byteArrayToString(desKey2.getEncoded());
			System.out.println(CryptoLib.byteArrayToString(encryptPuzzle) + "Key: " + desKeyStr + desKey2.getEncoded().length);
			

		}
		
		//write encrypted puzzles to file
		PrintWriter writer = new PrintWriter("OutputEncryptedPuzzle.txt", "UTF-8");
		for(int i = 0; i < puzzleEncrypted.size(); i ++){
			writer.println(puzzleEncrypted.get(i));
			
		}
		writer.close();
	}
	
	public static SecretKey generateRandomKey() throws NoSuchAlgorithmException{
		//Use java's key generator to produce a random key.
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
		keyGenerator.init(56);
		
		SecretKey secretKey = keyGenerator.generateKey();
		
		//print the key
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		//System.out.println(encodedKey);

		return secretKey;
	}
}
