/**
 * Author: Spencer Little (mrlittle@uw.edu)
 * An implementation of the AES (Rijndael) cipher
 */

import java.util.Scanner;
import java.io.File;
import java.io.IOException;

public class AES {

    public static byte[][] stateArray; // The state (two dimensional array containing 128 bit block of input data)
    public static String filePath; // Path to the file to be encrypted

    /*
     * Performs the cipher operations
     * Usage: -f path to file to be encrypted -o name of file for output -k key file  -m mode (CBC, tbd...)
     * @params command line arguments specifying cipher parameters
     */
    public static void main(String[] args) {
        stateArray = new byte[4][4];
        // parse cli https://stackoverflow.com/questions/367706/how-do-i-parse-command-line-arguments-in-java
        // http://commons.apache.org/proper/commons-cli/
    }

    /*
     * Reads 128 bits from the specified filepath into the state array
     */
    private void readFileData() {

        Scanner fileInput = null;
        try {
            fileInput = new Scanner(new File(filePath));
            int i = 0, j = 0;
            while (fileInput.hasNextByte() && i < 4) {
                stateArray[i][j] = fileInput.nextByte();;
                j++;
                if (j==4) {i++; j = 0;}
            }
        } catch (IOException iox) {
            System.out.println("Error occurred during reading of file.");
            iox.printStackTrace();
        } finally {
            if (fileInput != null) {
                fileInput.close();
            }
        }
    }

}
