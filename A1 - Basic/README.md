# Cryptography

secureFile.java
    This is the program which encrypts the file that you provide to it in the command line along with a seed.

    How to:
    		In terminal, type the command "javac secureFile.java" followed by "java secureFile input.txt output.txt seed"; this will encrypt the input.txt file with a randomly generated number sequence using the seed, and output the encrypted output.txt file.

    Algorithm:
    		A 128 bit AES key is created along with the seed using SHA-1. The encryption process generates the message digest using DSA/SHA-1 and attaches the length of the digest at the start of the file, which is followed by the number sequence of the digest and finished with the message.

    Test:
    		The program is compatible with txt, jpeg, and zip files.


decryptFile.java
    This is the program which decrypts the file indicated in the first argument of the command line along with a seed.

    How to:
    		In terminal, type the command "javac decryptFile.java" followed by "java decryptFile input.txt output.txt seed"; this will decrypt the input.txt file with the passed seed, and output the original output.txt file.

    Algorithm:
    		A 128 bit AES key is reconstructed from the seed using SHA-1.
    		The crypto message is deciphered which is then parssed by taking the first byte element from the text, extracting the size of the sig number fir the DSA and then itterating over the text to obtain the sig number. Before the output is generated these excess bytes are removed.

    Test:
    		The program decrypts txt, jpeg, and zip files.


Known Bugs:
-The verify in the secureFile.java works and returns true however, when extracting the sig number in the decryptFile.java the verify returns false. I manually checked to make sure that no bits were changed and compared the SHA-1 hash generated in the decryptFile.java with the one generated in secureFile.java and they both match.