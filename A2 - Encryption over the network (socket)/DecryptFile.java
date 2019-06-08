import java.io.*;
import javax.crypto.spec.*;

/**
 * This program performs the following cryptographic operations on the input file:
 *   - computes a random 128-bit key (1st 16 bits of SHA-1 hash of a user-supplied seed)
 *   - decrypts the file
 *   - extracts a HMAC-SHA1 digest of the original file contents (from the end of the
 *     decrypted data)
 *   - computes the HMAC-SHA1 digest of the decrypted file contents
 *   - outputs the encrypted data if the computed and decrypted digests are equal
 *
 * Compilation:    javac DecryptFile.java
 * Execution: java DecryptFile [plaintext-filename] [ciphertext-filename] [seed]
 *
 * @author Luke Iremadze
 * @version 1.0, November 11, 2018
 */
public class DecryptFile extends FileEncryption {

	DecryptFile(String inputFile, String outputFile, String seed) throws IOException {
		super(inputFile, outputFile, seed);

	}

    public void process() throws Exception {


	try{
	    // open input and output files
		setIn_file(new FileInputStream(getInputFile()));
		setOut_file(new FileOutputStream(getOutputFile()));


	    // read input file into a byte array
        byte[] msg = new byte[getIn_file().available()];
	    int read_bytes = getIn_file().read(msg);

        //Read cipher text file

        getIn_file().read(msg);

	    // compute key:  1st 16 bytes of SHA-1 hash of seed
	    SecretKeySpec key = CryptoUtilities.key_from_seed(getSeed().getBytes());

	    // do AES decryption
	    byte[] hashed_plaintext = CryptoUtilities.decrypt(msg,key);

	    // verify HMAC-SHA-1 message digest and output plaintext if valid
	    if (CryptoUtilities.verify_hash(hashed_plaintext,key)) {
			System.out.println("Message digest OK");
			setPass(true);

			// extract plaintext and output to file
			byte[] plaintext = CryptoUtilities.extract_message(hashed_plaintext);
			getOut_file().write(plaintext);
				getOut_file().close();
	    }
	    else System.out.println("ERROR: invalid message digest!");
	}
	catch(Exception e){
	    System.out.println(e);
	}
	finally{
	    if (getIn_file() != null){
		getIn_file().close();
	    }
	}
    }

}