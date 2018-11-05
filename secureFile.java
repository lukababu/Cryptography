/**
Title:  File Encryption
Author: Luke Iremadze
Date:   November 4, 2018
 */
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.util.Arrays;

public class secureFile {
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
        byte[] hmac_hash = null;
        byte[] aes_ciphertext = null;
        byte[] sig = null;
        String decrypted_str = new String();
        int read_bytes = 0;
        boolean verify = false;

        try{
            //open files
            in_file = new FileInputStream(inputFileDir);     // plaintext
            out_file = new FileOutputStream(outputFileDir);   // ciphertext

            //read file into a byte array
            byte[] msg = new byte[in_file.available()];
            read_bytes = in_file.read(msg);

            //SHA-1 Hash
            sha_hash = sha1_hash(msg);

            //print out hash in hex
            System.out.println("Message SHA-1 Hash: " + toHexString(sha_hash));

            //key setup - generate 128 bit key using SHA-1
            byte[] seedByte = seed.getBytes();
            byte[] seedHash = sha1_hash(seedByte);

            //get key by getting the first 16 bytes
            raw = Arrays.copyOfRange(seedHash, 0, 16);
            sec_key_spec = new SecretKeySpec(raw, "AES");

            //create the cipher object that uses AES as the algorithm
            sec_cipher = Cipher.getInstance("AES");

            //sign the SHA-1 hash of the file with DSA
            sig = generateDSASig(sha_hash);
            big_sig = new BigInteger(sig);
            System.out.println("sig in big int form: " + big_sig);
            byte sigLengthBuff = (byte)sig.length;
            byte[] sigLength = {sigLengthBuff};

            //verify signature
            verify = verifyDSASig(sig, sha_hash);
            System.out.println("Signature verified? " + verify);


            // Concatenate the length and big sig numbers to the cypher text
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write( sigLength );
            outputStream.write( sig );
            outputStream.write( msg );

            //do AES encryption
            aes_ciphertext = aes_encrypt(outputStream.toByteArray( ));
            System.out.println("encrypted file: " + toHexString(aes_ciphertext));

            // Generate output
            out_file.write(aes_ciphertext);
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

    public static byte[] aes_encrypt(byte[] data_in) throws Exception{
        byte[] out_bytes = null;
        try{
            //set cipher object to encrypt mode
            sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec);

            //create ciphertext
            out_bytes = sec_cipher.doFinal(data_in);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return out_bytes;
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

    public static byte[] hmac_sha1(byte[] in_data) throws Exception{
        byte[] result = null;

        try{
            //generate the HMAC key
            KeyGenerator theKey = KeyGenerator.getInstance("HMACSHA1");
            SecretKey secretKey = theKey.generateKey();

            Mac theMac = Mac.getInstance("HMACSHA1");
            theMac.init(secretKey);

            //create the hash
            result = theMac.doFinal(in_data);
        }
        catch(Exception e){
            System.out.println(e);
        }
        return result;
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


