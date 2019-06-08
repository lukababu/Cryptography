import java.io.*;
import java.net.*;
import java.util.Scanner;

/**
 * Client program.  Connects to the server and sends text accross.
 */

public class Client
{
    private static String seed;
    private Socket sock;  //Socket to communicate with.
    private static String INPUTFILE = "message.txt";
    private static String OUTPUTFILE = "clientoutput\\ciphertext.txt";
    private static final int CHUNK_SIZE = 1024;

    /**
     * Main method, starts the client.
     * @param args args[0] needs to be a hostname, args[1] a port number.
     */
    public static void main (String [] args) throws IOException {
        if (args.length != 2) {
            System.out.println ("Usage: java Client hostname port#");
            System.out.println ("hostname is a string identifying your server");
            System.out.println ("port is a positive integer identifying the port to connect to the server");
            return;
        }
        System.out.println("======================================");
        System.out.println("Encrypt file and send over the network");
        System.out.println("======================================");

        try {
            Client c = new Client (args[0], Integer.parseInt(args[1]));
        }
        catch (NumberFormatException e) {
            System.out.println ("Usage: java Client hostname port#");
            System.out.println ("Second argument was not a port number");
            return;
        }
    }

    public Client (String ipaddress, int port) throws IOException {
        /* Allows us to get input from the keyboard. */
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        Scanner input = new Scanner(System.in);
        //File message = new File(INPUTFILE);
        //FileInputStream fin = new FileInputStream(message);
        //byte b[] = new byte[(int)message.length()];
        //fin.read(b);
        //stdIn.read(b);

        String userinput;
        PrintWriter out;

        /* Try to connect to the specified host on the specified port. */
        try {
            sock = new Socket (InetAddress.getByName(ipaddress), port);
        }
        catch (UnknownHostException e) {
            System.out.println ("Usage: java Client hostname port#");
            System.out.println ("First argument is not a valid hostname");
            return;
        }
        catch (IOException e) {
            System.out.println ("Could not connect to " + ipaddress + ".");
            return;
        }

        /* Status info */
        System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);

        try {
            out = new PrintWriter(sock.getOutputStream());
        }
        catch (IOException e) {
            System.out.println ("Could not create output stream.");
            return;
        }

        System.out.print("Enter seed: ");
        seed = input.nextLine();

        System.out.println("\nEncrypting file...");
        SecureFile secureFile = new SecureFile(INPUTFILE, OUTPUTFILE, seed);
        secureFile.process();
        System.out.println("File Encrypted.");

        System.out.println("Sending File...");
        sendFile(sock, OUTPUTFILE);

        /* Wait for the user to type stuff. */
        try {
            while ((userinput = stdIn.readLine()) != null) {
                /* Echo it to the screen. */
                out.println(userinput);

                /* Tricky bit.  Since Java does short circuiting of logical
                 * expressions, we need to checkerror to be first so it is always
                 * executes.  Check error flushes the outputstream, which we need
                 * to do every time after the user types something, otherwise,
                 * Java will wait for the send buffer to fill up before actually
                 * sending anything.  See PrintWriter.flush().  If checkerror
                 * has reported an error, that means the last packet was not
                 * delivered and the server has disconnected, probably because
                 * another client has told it to shutdown.  Then we check to see
                 * if the user has exitted or asked the server to shutdown.  In
                 * any of these cases we close our streams and exit.
                 */
                if ((out.checkError()) || (userinput.compareTo("exit") == 0) || (userinput.compareTo("die") == 0)) {
                    System.out.println("Client exiting.");
                    stdIn.close();
                    out.close();
                    sock.close();
                    return;
                }
            }
        } catch (IOException e) {
            System.out.println ("Could not read from input.");
            return;
        }
    }

    public void sendFile(Socket s, String file) throws IOException {
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());
        FileInputStream fis = new FileInputStream(file);
        byte[] buffer = new byte[file.length()];

        while (fis.read(buffer) > 0) {
            dos.write(buffer);
        }
        System.out.println("File Sent!");

        fis.close();
        dos.close();
    }
}