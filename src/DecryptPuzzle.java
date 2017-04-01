import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
import java.lang.System.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
public class DecryptPuzzle {
	public static void main(String args[]) throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		Random rnd = new Random();
		String rndLine = Files.readAllLines(Paths.get("OutputEncryptedPuzzle.txt")).get(rnd.nextInt(1023));
		BufferedReader brTest = new BufferedReader(new FileReader("OutputEncryptedPuzzle.txt"));
	    String fileFirstPuzzle = brTest.readLine();
	    byte[] fileFirstPuzzleBytes = new byte[32];
	    fileFirstPuzzleBytes = CryptoLib.stringToByteArray(rndLine);
	    if (fileFirstPuzzle==""){
	    	//break;
	    }
	    byte[] allZeros = new byte[32];
	    Arrays.fill(allZeros,0,26,(byte)0);
	    String allzerosStr = Base64.getEncoder().encodeToString(allZeros);
	    
	    //testing decryption with actual key
	    String actualKeyStr = "6kkAAAAAAAA=";
	    byte[] actualKey = CryptoLib.stringToByteArray(actualKeyStr);
	    //SecretKey desAttempt = CryptoLib.createKey(actualKey);
	    
	    
	    for (int i = 0; i<65536;i++){
	    	
	    	byte[] crackAttempt = new byte[8];
	    	crackAttempt[0] = (byte) (i / 256);
	    	crackAttempt[1] = (byte) Math.floor(i % 256);
	    	//System.out.println("Encrypted puzzle: " + fileFirstPuzzle);
	    	SecretKey desAttempt = CryptoLib.createKey(crackAttempt);
	    	
	    	Cipher decryptionCipher = Cipher.getInstance("DES");
			decryptionCipher.init(Cipher.DECRYPT_MODE, desAttempt);
			byte[] decryptedPuzzle = new byte[32];
			try {
			//System.out.println(decryptedPuzzle.length);
				decryptedPuzzle = decryptionCipher.doFinal(fileFirstPuzzleBytes);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
			}
			if (decryptedPuzzle.length == 26){
				System.out.println(CryptoLib.byteArrayToString(decryptedPuzzle) + "key " + CryptoLib.byteArrayToString(desAttempt.getEncoded()));
			}
	    	
			
	    	/*
	    	byte[] nonZeroKey = new byte[2];
	    	nonZeroKey = smallIntToByteArray(i);
			byte[] desBytes = new byte[8];
			byte[] zeros = new byte[6];
			
			Arrays.fill(zeros, 0, 6, (byte)0);
			System.arraycopy(zeros,0,desBytes,0,zeros.length);
			System.arraycopy(nonZeroKey,0,desBytes,zeros.length,nonZeroKey.length);
			SecretKey desKey = generateRandomKey();
			desBytes = desKey.getEncoded();
			desKey = createKey(desBytes);
			if((i%1000)==0){
				System.out.println(i);
			}
			System.out.println(desBytes.length);
			Cipher decryptionCipher = Cipher.getInstance("DES");
			decryptionCipher.init(Cipher.DECRYPT_MODE, desKey);
			
			//convert to UTF for encryption
			//byte[] puzzleInUTF8 = puzzleStr.getBytes("UTF8");
			 byte[] fileFirstPuzzleBytesDe = new byte[26];
			fileFirstPuzzleBytesDe = decryptionCipher.doFinal(fileFirstPuzzleBytes);
			String finalAnswer = Base64.getEncoder().encodeToString(fileFirstPuzzleBytesDe);
			boolean correct = true;
			for (int j = 0; j<128;j++){
				if(fileFirstPuzzleBytesDe[j]!= (byte)0){
					correct = false;
					break;
				}

			}


			if (correct){
				System.out.println("it Fucking works");
				break;
			}
			
			*/
	    }
	    /*		
	    for(int i = 0; i < 65536; i++){
	    	
	    	byte[] attempt = new byte[2];
	    	attempts[0] = i / 256;
	    	attempts[1] = i % 256;
	    }
	     */
	    	

}
public static byte[] smallIntToByteArray(int i){
		if(i >= 65536){
			throw new IllegalArgumentException("Integer too large, expected range 0-65535.");
		}
		else{
			byte[] bytesOfNumber = ByteBuffer.allocate(4).putInt(i).array();
			return Arrays.copyOfRange(bytesOfNumber,2,4);
		}
	}
public static SecretKey generateRandomKey() throws NoSuchAlgorithmException{
		//Use java's key generator to produce a random key.
		KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
		keyGenerator.init(56);
		
		SecretKey secretKey = keyGenerator.generateKey();
		
		//print the key
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

		return secretKey;
	}
	public static SecretKey createKey(byte[] keyData) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException
	{
		if(keyData.length != 8){
			throw new IllegalArgumentException("Incorrect Array length expecting 64-bits / 8 bytes.");
		}
		else{
			SecretKeyFactory sf = SecretKeyFactory.getInstance("DES");
			DESKeySpec keySpec = new DESKeySpec(keyData);
			return sf.generateSecret(keySpec);
		}
	}

}