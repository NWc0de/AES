/*
 * Author: Spencer Little
 * Date: 09/14/2019
 * An implementation of CBC and CTR mode AES encryption/decryption via cli program, operates on files.
 */
package main;

import cipher.AES;
import cipher.AESCTR;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Performs encryption/decryption (via CLI arguments) operations using the AES class
 * @author Spencer Little
 * @version 1.0.0
 */
final class CliCipher extends AES {

    private int toPad;
    private FileInputStream fileInput;
    private FileOutputStream fileOutput;
    private int bytesToCipher;
    private int fileSize;
    private static Args cliArgs;

    /**
     * Orchestrates the cipher operations
     * @params command line arguments specifying cipher parameters
     */
    public static void main(String[] argv) {
        CliCipher crypt = new CliCipher();
        cliArgs = new Args();
        try {
            JCommander.newBuilder().addObject(cliArgs).build().parse(argv);
        } catch (ParameterException prx) {
            System.out.println("Path to the plaintext, path to the initialization vector, output filename, and key file path must be specified.");
            Args.showHelp();
            System.exit(1);
        }
        if (cliArgs.help) {
            Args.showHelp();
            System.exit(1);
        }

        crypt.initializeFileOperators();
        crypt.readKeyFile();
        crypt.keyExpansion();
        crypt.readInitVectorFile();


        if (!cliArgs.counterMode && cliArgs.decrypt) {
            crypt.cipherBlockChainDecrypt();
        } else if (!cliArgs.counterMode){
            crypt.cipherBlockChainEncrypt();
        } else if (cliArgs.decrypt) {
            crypt.counterModeDecrypt();
        } else {
            crypt.counterModeEncrypt();
        }

        try {
            crypt.closeFileOperators();
        } catch (IOException iox) {
            System.out.println("Error closing file operators.");
            iox.printStackTrace();
            System.exit(1);
        }
        System.out.println("Cipher operations successful. Processed " + crypt.fileSize + " bytes.");
    }

    /*
    ------------------------------------------
              Encryption/Decryption
    ------------------------------------------
     */

    /*
     * Counter mode ref. NIST SP 800 38a (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
     */
    private void counterModeEncrypt() {
        byte[] fileBytes = readDataFile();
        fileBytes = AESCTR.padByteArray(fileBytes);
        AESCTR counterCrypt = new AESCTR(fileBytes, getInitKeyBytes(), initializationVector);
        fileBytes = counterCrypt.counterModeCipher();
        writeByteArrayToFile(fileBytes);
    }

    private void counterModeDecrypt() {
        byte[] fileBytes = readDataFile();
        AESCTR counterCrypt = new AESCTR(fileBytes, getInitKeyBytes(), initializationVector);
        fileBytes = counterCrypt.counterModeCipher();
        fileBytes = AESCTR.removePadding(fileBytes);
        writeByteArrayToFile(fileBytes);
    }

    /*
     * Cipher block chain mode ref. NIST SP 800 38a (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
     */
    private void cipherBlockChainEncrypt() {
        while(readBlockOfDataFile()) {
            xorVectorWithState(); // xor the IV, or the previous ciphertext block with the state
            cipher();
            writeStateToFile();
            initializationVector = deepCopy(stateArray);
        }
        try {
            applyPadding();
            xorVectorWithState();
            cipher();
            writeStateToFile();
            closeFileOperators();
        } catch (IOException iox) {
            System.out.println("Error writing final block to file.");
            iox.printStackTrace();
        }
    }

    private void cipherBlockChainDecrypt() {
        while(readBlockOfDataFile()) {
            int[][] temp = deepCopy(stateArray);
            invCipher();
            xorVectorWithState();
            writeStateToFile();
            initializationVector = deepCopy(temp);
        }
        try {
            invCipher();
            xorVectorWithState();
            writeFinalBlock();
            closeFileOperators();
        } catch (IOException iox) {
            System.out.println("Error writing final block to file.");
            iox.printStackTrace();
        }
    }

    /*
    ------------------------------------------
                   I/O Methods
    ------------------------------------------
     */

    private void initializeFileOperators() {
        try {
            fileInput = new FileInputStream(cliArgs.filePath);
            bytesToCipher = fileInput.available();
            fileSize = bytesToCipher;
            File output = new File(cliArgs.output);
            if (output.exists()) {
                System.out.println("Please specify a unique filename with an appropriate extension");
                System.exit(1);
            }
            fileOutput = new FileOutputStream(cliArgs.output, true);
        } catch (IOException iox) {
            System.out.println("Error occurred while creating file stream.");
            iox.printStackTrace();
            System.exit(1);
        }
    }

    /*
     * Reads 128 bits from the specified filepath into the state array per NIST specification (ref. pg.9 sec 3.4)
     */
    private boolean readBlockOfDataFile() {
        boolean isBlockAvailable = true;
        try {
            if (bytesToCipher >= 16) {
                int i = 0, j = 0;
                while (i < 4) {
                    stateArray[j][i] = fileInput.read();
                    j++;
                    if (j == 4) {i++; j = 0;}
                }
                bytesToCipher -= 16;
            } else {
                isBlockAvailable = false;
                toPad = (bytesToCipher == 0) ? 16 : 16 - bytesToCipher;
            }
        } catch (IOException iox) {
            System.out.println("Error occurred while reading file.");
            iox.printStackTrace();
            System.exit(1);
        }
        return isBlockAvailable;
    }

    /*
     * Reads entire file and returns as byte array
     */
    private byte[] readDataFile() {
        byte[] fileBytes;
        try {
            fileBytes = new byte[fileInput.available()];
            fileInput.read(fileBytes);
        } catch (IOException iox) {
            fileBytes = null;
            System.out.println("Error occurred while reading file.");
            iox.printStackTrace();
            System.exit(1);
        }
        return fileBytes;
    }

    private void writeByteArrayToFile(byte[] byteArray) {
        try {
            fileOutput.write(byteArray);
        } catch (IOException iox) {
            System.out.println("Error writing data to file.");
            iox.printStackTrace();
        }
    }

    /*
     * Apply PKCS#7 padding
     * Even if no padding is required an extra block is added
     */
    private void applyPadding() throws java.io.IOException {
        int toRead = 16 - toPad;
        int i = 0, j = 0, padded = 0;
        while (toRead > 0 || padded < toPad) {
            if (toRead > 0) {
                stateArray[j][i] = fileInput.read();
                toRead--;
            }
            if (padded < toPad) {
                stateArray[3 - j][3 - i] = toPad;
                padded++;
            }
            j++;
            if (j == 4) {i++; j = 0;}
        }
    }

    /*
     * Removes padding, assumes final block will always be padded
     */
    private void writeFinalBlock() throws IOException {
        int toWrite = 16 - stateArray[3][3];
        int i = 0, j = 0;
        while (toWrite > 0) {
            fileOutput.write(stateArray[j][i]);
            toWrite--;
            j++;
            if (j == 4) {i++; j = 0;}
        }
    }

    private void closeFileOperators() throws java.io.IOException {
        fileOutput.close();
        fileInput.close();
    }

    private void writeStateToFile() {
        try {
            int i = 0, j = 0, toWrite = 0;
            while (toWrite < 16) {
                fileOutput.write(stateArray[j][i]);
                j++; toWrite++;
                if (j == 4) {i++; j = 0;}
            }
        } catch (IOException iox) {
            System.out.println("Error writing data to file.");
            iox.printStackTrace();
        }
    }

    /*
     * Reads data from the specified key file into the roundKeys array
     */
    private void readKeyFile() {
        try {
            FileInputStream keyFileInput = new FileInputStream(cliArgs.keyFilePath);
            keySize = keyFileInput.available()/4; // determine the number of 32 bit words in the key
            roundKeys = new int[4][4 * ((keySize)+7)]; // the number of 32 bit words in the expanded key
            int i = 0;                                  // is equal (Nr + 1)*Nb where Nr = the number of rounds
            do {                                       // (which is equal to (Nk + 6), Nb = columns in the state array
                for (int j = 0; j < 4; j++) {         // and Nk = number of 32 bit words in the key
                    roundKeys[j][i] = keyFileInput.read();
                }
                i++;
            } while (i+1 <= keySize);
        } catch (IOException iox) {
            System.out.println("Error occurred while reading key file. Is key appropriate length? (Acceptable lengths are 16, 24, or 32 bytes)");
            iox.printStackTrace();
            System.exit(1);
        }
        if (keySize > 8 || keySize <= 2 || keySize%2==1) {
            System.out.println("Invalid key length. Acceptable lengths are: 128, 192, or 256 bits.");
            System.exit(1);
        }
    }

    private void readInitVectorFile() {
        try {
            FileInputStream initVectorInput = new FileInputStream(cliArgs.initVectorFilePath);
            if (initVectorInput.available() != 16) {
                System.out.println("Invalid byte length of IV file. Initialization vector file must contain exactly 16 bytes.");
                System.exit(1);
            }
            int i = 0, j = 0;
            while ((i*4) < 16) {
                initializationVector[j][i] = initVectorInput.read();
                j++;
                if (j == 4) {i++; j = 0;}
            }
        } catch (IOException iox) {
            System.out.println("Error occurred while reading initialization vector file");
            iox.printStackTrace();
            System.exit(1);
        }
    }

}
