import java.io.IOException;

public class Main {

    public static void main(String[] args) throws Exception {

        System.out.println("Hello World!");

        SecureFile secureFile = new SecureFile("message.txt", "output.txt", "luka");
        secureFile.process();

        DecryptFile decryptFile = new DecryptFile("output.txt", "translation.txt", "luka");
        decryptFile.process();
    }
}
