=============================
    |   CPSC 413        |
    |   Luke Iremadze   |
    |   10163614        |
    |   T03             |
=============================

FileEncryption.java
    This is the program which encrypts hold all the variables necessary for SecureFile and DecryptFile to function.

    Description: A helper class, child of FileEncryption. All data integrity is handled by this parent class, which has hides key variables from classes outside.

SecureFile.java
    This is the program which encrypts the file that you provide to it in the command line along with a seed.

    Description: A helper class, child of FileEncryption

    Algorithm:
    		A 128 bit AES key is created along with the seed using SHA-1. The encryption process generates the message digest using DSA/SHA-1 and attaches the length of the digest at the start of the file, which is followed by the number sequence of the digest and finished with the message.

DecryptFile.java
    This is the program which decrypts the file upon creating an object of DecryptFile.

    Description: A helper class, child of FileEncryption

    Algorithm:
    		A 128 bit AES key is reconstructed from the seed using SHA-1.
    		The crypto message is deciphered which is then parssed by taking the first byte element from the text, extracting the size of the sig number fir the DSA and then itterating over the text to obtain the sig number. Before the output is generated these excess bytes are removed.

Client.java
    This is a client side program that connects to a server listening on the same port. 


    Algorithm:
	Uses TCP protocol to establish and send content over the network. It asks for a seed from user and encrypts the file in folder "clientoutput" T

Server.java
    The program binds to a port number on the network and listens for incomming connections.

    Algorithm:
    		Upon established connection, the Server.java passes on handeling the client-server interaction to ServerThread

ServerThread.java
    This is the program which handles all the interaction with the client.

    Algorithm:
    		A 128 bit AES key is reconstructed from the seed using SHA-1.
    		The crypto message is deciphered which is then parssed by taking the first byte element from the text, extracting the size of the sig number fir the DSA and then itterating over the text to obtain the sig number. Before the output is generated these excess bytes are removed.

    Test:
    		The program decrypts txt, jpeg, and zip files.


Known Bugs:
-The server is not able to decrypt the file. empty file generated!