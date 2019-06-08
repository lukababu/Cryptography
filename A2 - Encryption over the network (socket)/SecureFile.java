import java.io.*;
import javax.crypto.spec.*;

/**
 * This program performs the following cryptographic operations on the input file:
 *   - computes a random 128-bit key (1st 16 bits of SHA-1 hash of a user-supplied seed)
 *   - computes a HMAC-SHA1 hash of the file's contents
 *   - encrypts the file+hash using AES-128-CBC
 *   - outputs the encrypted data
 *
 * Compilation:    javac SecureFile.java
 * Execution: java SecureFile [plaintext-filename] [ciphertext-filename] [seed]
 *
 * @author Luke Iremadze
 * @version 1.0, November 11, 2018
 */
public class SecureFile extends FileEncryption {

    SecureFile(String inputFile, String outputFile, String seed) throws IOException {
        super(inputFile, outputFile, seed);
    }

    public void process() throws IOException {

	try{
	    // open input and output files
	    setIn_file(new FileInputStream(getInputFile()));
	    setOut_file(new FileOutputStream(getOutputFile()));

	    // read input file into a byte array
	    byte[] msg = new byte[getIn_file().available()];
	    int read_bytes = getIn_file().read(msg);

	    // compute key:  1st 16 bytes of SHA-1 hash of seed
	    SecretKeySpec key = CryptoUtilities.key_from_seed(getSeed().getBytes());

	    // append HMAC-SHA-1 message digest
	    byte[] hashed_msg = CryptoUtilities.append_hash(msg,key);

	    // do AES encryption
	    byte[] aes_ciphertext = CryptoUtilities.encrypt(hashed_msg,key);

	    // output the ciphertext
	    getOut_file().write(aes_ciphertext);
	    getOut_file().close();
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