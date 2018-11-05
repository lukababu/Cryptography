/**
Title:  File decryption
Author: Luke Iremadze
Date:   November 4, 2018
 */
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

public class decryptFile {
    private static byte[] raw = null;
    private static SecretKeySpec sec_key_spec = null;
    private static Cipher sec_cipher = null;

    //for DSA
    private static KeyPairGenerator keypairgen = null;
    private static KeyPair keypair = null;
    private static DSAPrivateKey private_key = null;
    private static DSAPublicKey public_key = null;
    private static Signature dsa_sig = null;
    private static SecureRandom secRan = null;
    private static BigInteger big_sig = null;

    public static void main(String args[]) throws Exception{
        String inputFileDir = args[0];
        String outputFileDir = args[1];
        String seed = args[2];

        FileInputStream in_file = null;
        FileOutputStream out_file = null;

        byte[] sha_hash = null;
        byte[] sig_file = null;
        byte[] sig_generated = null;
        byte[] decrypted_msg = null;
        boolean verify = false;

        try{
            //open files
            in_file = new FileInputStream(inputFileDir);
            out_file = new FileOutputStream(outputFileDir);

            //key setup - recover 128 bit key using SHA-1
            byte[] seedByte = seed.getBytes();
            byte[] seedHash = sha1_hash(seedByte);

            //get key by getting the first 16 bytes
            raw = Arrays.copyOfRange(seedHash, 0, 16);
            sec_key_spec = new SecretKeySpec(raw, "AES");

            //create the cipher object that uses AES as the algorithm
            sec_cipher = Cipher.getInstance("AES");

            //Read cipher text file
            byte[] ciphtext = new byte[in_file.available()];
            in_file.read(ciphtext);


            // Decrypt
            decrypted_msg = aes_decrypt(ciphtext);

            //Get length of big sig
            int sigLength = (decrypted_msg[0] & 0xFF);
            sig_file = new byte[sigLength];
            //System.out.println("The length of sig_file is: " + sigLength);

            // Get Sig numbers
            for (int j = 0; j < sigLength; j++) {
                sig_file[j] = decrypted_msg[j+1];
                //System.out.println("Check " + j);
            }
            big_sig = new BigInteger(sig_file);
            //System.out.println("sig_file in big int form: " + big_sig);

            // Format output
            int outputMessageLenght = decrypted_msg.length - (sigLength+1);
            //System.out.println("The length is: " + outputMessageLenght);
            byte[] output_msg = new byte[outputMessageLenght];
            for (int j = 0; j < outputMessageLenght; j++) {
                output_msg[j] = decrypted_msg[(sigLength+1)+j];
            }

            // Generate the hash with the decrypted message
            sha_hash = sha1_hash(output_msg);
            System.out.println("Message SHA-1 Hash: " + toHexString(sha_hash));

            // activate public keys
            sig_generated = generateDSASig(sha_hash);

            //verify signature
            verify = verifyDSASig(sig_file, sha_hash);
            System.out.println("Signature verified? " + verify);

            //Write Output file
            out_file.write(output_msg);
            out_file.close();

        }
        catch(Exception e){
            System.out.println(e);
        }
        finally{
            if (in_file != null){
                in_file.close();
            }
            if(out_file != null){
                out_file.close();
            }
        }
    }

    public static byte[] aes_decrypt(byte[] data_in) throws Exception{
        byte[] decrypted = null;
        String dec_str = null;
        try{
            //set cipher to decrypt mode
            sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec);

            //do decryption
            decrypted = sec_cipher.doFinal(data_in);

            //convert to string
            dec_str = new String(decrypted);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return decrypted;
    }

    public static byte[] sha1_hash(byte[] input_data) throws Exception{
        byte[] hashval = null;
        try{
            //create message digest object
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");

            //make message digest
            hashval = sha1.digest(input_data);
        }
        catch(NoSuchAlgorithmException nsae){
            System.out.println(nsae);
        }
        return hashval;
    }

    public static boolean verifyDSASig(byte[] signature, byte[] hash){
        boolean verified = false;

        try{
            //put signature in Verify mode
            dsa_sig.initVerify(public_key);

            //load the data to verify
            dsa_sig.update(hash);

            //get verification boolean
            verified = dsa_sig.verify(signature);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return verified;
    }

    public static byte[] generateDSASig(byte[] hash){
        byte[] ret = null;

        try{
            keypairgen = KeyPairGenerator.getInstance("DSA");
            secRan = SecureRandom.getInstance("SHA1PRNG");
            keypairgen.initialize(1024, secRan);
            keypair = keypairgen.generateKeyPair();

            //get private and public keys
            private_key = (DSAPrivateKey) keypair.getPrivate();
            public_key = (DSAPublicKey) keypair.getPublic();

            //make DSA object
            dsa_sig = Signature.getInstance("SHA/DSA");
            dsa_sig.initSign(private_key);
            dsa_sig.update(hash);
            ret = dsa_sig.sign();
        }
        catch(Exception e){
            System.out.println(e);
        }

        return ret;
    }

    /*
     * Converts a byte array to hex string
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
}
