/**
 * Author: Spencer Little (mrlittle@uw.edu)
 * Date: 08/28/18
 * An implementation of the AES (Rijndael) cipher
 */

import java.io.FileInputStream;
import java.io.IOException;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

public class AES {

    public static int[][] stateArray; // The state (two dimensional array containing 128 bit block of input data)
    public static Args cliArgs; // The cli object, facilitates parsing and specification of cli arguments
    public static FileInputStream fileInput; // class Scanner to read data from file

    /*
     * Orchestrates the cipher operations
     * Usage: -f, -filepath: path to file to be encrypted -o, -output: name of file for output -k, -key: key file
     * @params command line arguments specifying cipher parameters
     */
    public static void main(String[] argv) {
        stateArray = new int[4][4];
        fileInput = null;
        // Parse the cli arguments
        cliArgs = new Args();
        try {
            JCommander.newBuilder().addObject(cliArgs).build().parse(argv);
        } catch (ParameterException prx) { // extraneous parameters raise exception
            Args.showHelp();
            System.exit(1);
        }
        cipher();
    }

    /*
     * Performs one round of the cipher functions
     * @params null, uses class var state to perform operations
     * @return null, writes ciphertext to output array
     */
    private static void cipher() {
        for (int z = 0; z < 14; z ++) {
            readFileData();
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    System.out.println(stateArray[i][j]);
                }
            }
        }
    }

    /*
     * Reads 128 bits from the specified filepath into the state array
     */
    private static void readFileData() {
        if (fileInput == null) {
            try {
                fileInput = new FileInputStream(cliArgs.filePath);
            } catch (IOException iox) {
                System.out.println("Error occurred while creating file stream.");
                iox.printStackTrace();
                System.exit(1);
            }
        }
        // read data into state per NIST specification
        //TODO: Padding?
        try {
            int i = 0, j = 0;
            while (i < 4) {
                stateArray[j][i] = fileInput.read();
                j++;
                if (j == 4) { i++; j = 0; }
            }
        } catch (IOException iox) {
            System.out.println("Error occurred while reading file.");
            iox.printStackTrace();
            System.exit(1);
        }
        //TODO: Remember to close readers after final cipher loop
    }

}
