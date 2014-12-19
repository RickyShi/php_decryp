package php_decryp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;




public class decryp_main {

	static String path = "C:\\Users\\Ricky\\Desktop\\D\\";
	static String file = "Location.0000.D_11.txt";

	public static void main(String[] args){

		try {
			decrpytion();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	protected static void writeToFile(File f, String toWrite) throws IOException{
		FileWriter fw = new FileWriter(f, true);
		fw.write(toWrite+'\n');
        fw.flush();
		fw.close();
	}

	protected static void decrpytion() throws Exception {
		// TODO Auto-generated method stub

		Key privKey = readPublicFromFile(path + "private.key");
		System.out.println(path + "RSA -------- private.key");
        System.out.println("format is "+privKey.getFormat());
        System.out.println("algorithm is "+privKey.getAlgorithm());
        System.out.println("encoded is "+privKey.getEncoded());
        System.out.println("length is "+privKey.getEncoded().length);
        System.out.println(path + "RSA -------- ");

        Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
		cipher.init(Cipher.DECRYPT_MODE, privKey);

		FileInputStream input = new FileInputStream(path + file);
		//		input.skip(473);

		FileInputStream f = new FileInputStream(path + file);
		// DataInputStream dr = new DataInputStream(f);
		BufferedReader dr = new BufferedReader(new InputStreamReader(f));
		String line = dr.readLine();
		int se = 0;
		while (line != null) {
			System.out.println(line);
			line = dr.readLine();
			se++;
		}

		System.out.println("se is " + se);

		byte[] b = new byte[input.available()];
		int numofbyte = input.read(b);
		//Log.d(TAG,"byte length is "+b.length);


		//////////////////////////////
		byte[] b2 = Base64.decodeBase64(b);
		//		byte [] b2=Base64.decodeBase64(str);
		/////////////////////////////

		for (byte by : b) {
			System.out.println(by);
		}

		System.out.println("numofbyte is " + numofbyte);
		System.out.println("b size is " + b.length);
		System.out.println("b2 size is " + b2.length);

		byte [] keybyte = Arrays.copyOfRange(b2, 0, 256);
		byte [] filebyte = Arrays.copyOfRange(b2, 256, b2.length);

		System.out.println("keybyte size is "+keybyte.length);
		System.out.println("filebyte size is "+filebyte.length);

		byte [] keyre = cipher.doFinal(keybyte);
		System.out.println("keyre size is "+keyre.length);
		System.out.println("key is " + new String(keyre));
		System.out.println("key is " + new String(Base64.encodeBase64(keyre)));


		//
		//byte array keyre to key    keyre->key

		SecretKeySpec secretKeySpec = new SecretKeySpec(keyre, "AES");

		Cipher cipherAes = Cipher.getInstance("AES");
		cipherAes.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte [] result=cipherAes.doFinal(filebyte);
        //fisDat.close();
        //baos.close();

        System.out.println("result is " + new String(result));


		FileOutputStream output = new FileOutputStream(path + "final.txt");
		//        FileOutputStream output = new FileOutputStream(path + str1);
        output.write(result);
        output.close();

	}



	public static PublicKey readPublicFromFile(String fileName)
	{
		try{
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
				BigInteger m = (BigInteger)ois.readObject();
				BigInteger e = (BigInteger)ois.readObject();
			    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
			    KeyFactory fact = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
			    PublicKey pubKey = fact.generatePublic(keySpec);
			return pubKey;
		}catch(Exception e){
			e.getMessage();
			return null;
		}
	}
}
