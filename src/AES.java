/**
 * Author: Spencer Little (mrlittle@uw.edu)
 * Date: 08/28/18
 * An implementation of the AES (Rijndael) cipher
 * ref. https://www.nist.gov/publications/advanced-encryption-standard-aes
 */

import java.io.FileInputStream;
import java.io.IOException;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

public class AES {

    public static int[][] stateArray; // The state (two dimensional array containing 128 bit block of input data)
    public static Args cliArgs; // The cli object, facilitates parsing and specification of cli arguments
    public static int[][] roundKeys; // The expanded round keys
    public static int keySize; // 4, 6, 8 depending on number of 32 bit words in the initial key
    public static FileInputStream fileInput;

    // The sbox table
    public static final int[][] sbox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

    /*
     * Orchestrates the cipher operations
     * Usage: -f, -filepath: path to file to be encrypted -o, -output: name of file for output -k, -key: key file
     * -e|encrypt or -d|decrypt
     * @params command line arguments specifying cipher parameters
     */
    public static void main(String[] argv) {
        stateArray = new int[4][4];
        fileInput = null;
        // Parse the cli arguments
        cliArgs = new Args();
        try { //TODO: Handle case in which insufficient arguments are provided
            JCommander.newBuilder().addObject(cliArgs).build().parse(argv);
        } catch (ParameterException prx) { // extraneous parameters raise exception
            Args.showHelp();
            System.exit(1);
        }
        //TODO: Infer key length here
        cipher();
    }

    /*
    ------------------------------------------
                    Main Methods
    ------------------------------------------
     */

    /*
     * Performs one round of the cipher functions
     * @params null, uses class var state to perform operations
     * @return null, writes ciphertext to output array
     */
    public static void cipher() {
        readFileData();
        readKeyData();
    }

    /*
     * Reads 128 bits from the specified filepath into the state array
     * @return a boolean value indicating whether the final block of the final has been read
     * (true -> the final block has been read. false -> the final block has not been read.)
     */
    public static boolean readFileData() {
        if (fileInput == null) {
            try {
                fileInput = new FileInputStream(cliArgs.filePath);
            } catch (IOException iox) {
                System.out.println("Error occurred while creating file stream.");
                iox.printStackTrace();
                System.exit(1);
            }
        }
        // read data into state per NIST specification (ref. pg.9 sec 3.4)
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
        //TODO: return false if the last byte of the final has been read
        return false;
    }

    /*
     * Reads data from the specified key file into the roundKeys array
     */
    public static void readKeyData() {
        try {
            FileInputStream keyFileInput = new FileInputStream(cliArgs.keyFilePath);
            keySize = keyFileInput.available(); // determine the number of bytes in the key
            roundKeys = new int[4][ 4 * ((keySize/4)+7)]; // the number of 32 bit words in the expanded key
            int i = 0;                                  // is equal (Nr + 1)*Nb where Nr = the number of rounds
            do {                                       // (which is equal to (Nk + 6), Nb = columns in the state array
                for (int j = 0; j < 4; j++) {         // and Nk = number of 32 bit words in the key
                    roundKeys[j][i] = keyFileInput.read();
                }
                i++;
            } while (i+1 <= keySize/4);
        } catch (IOException iox) {
            System.out.println("Error occurred while reading key file");
            iox.printStackTrace();
            System.exit(1);
        }
    }

    /*
    ------------------------------------------
                    Cipher Methods
    ------------------------------------------
     */

    /*
     * Performs the byte substitution operation specified in the NIST standard (pg. 15 sec 5.1.1)
     */
    public static void subBytes() {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int x = stateArray[i][j] / 16; // each byte is divided into nibbles which form the
                int y = stateArray[i][j] % 16; // respective row and column indices for the sbox
                stateArray[i][j] = sbox[x][y];
            }
        }
    }

    /*
     * Shifts bytes in the last three rows (NIST AES specification pg. 17 sec 5.1.2)
     */
    public static void shiftRows() {
        for (int i = 1; i < 4; i++) {
            int[] tempRow = new int[4];
            System.arraycopy(stateArray[i], 0, tempRow, 0,4);
            for (int j = 0; j < 4; j++) {
                stateArray[i][j] = tempRow[(j + i)%4];
            }
        }
    }

    /*
     * Mixes columns (interpreted 32 bit words representing finite field elements over GF(2^8))
     * ref. NIST AES specification pg. 18 sec 5.1.3
     * Multiplication by 2 is accomplished with a left bit shift and conditional xor
     * Multiplication by three is accomplished by using the result from x2 then a xor with original byte
     * ref. (http://www.angelfire.com/biz7/atleast/mix_columns.pdf)
     * Note: The column mixing operation assures the plaintext is sufficiently diffused
     */
    public static void mixColumns() {
        for (int i = 0; i < 4; i++) {
            int[] cWord = new int[4];
            for (int j = 0; j < 4; j++) {
                cWord[j] = stateArray[j][i];
            }
            stateArray[i] = mixColumnWord(cWord);
        }
    }

    /*
     * A helper method for mixColumns
     * Performs the column mixing operations via galois multiplication
     * @params 32 bit word representing column of the state in the form of an array of bytes
     * @return 32 bit word after performing the multiplication operations
     * https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Rijndael_mix_columns.html
     */
    public static int[] mixColumnWord(int[] cWord) {
        int[] outWord = new int[4];
        int[] wordByTwo = new int[4];
        for (int i = 0; i < 4; i++) {
            int h = cWord[i] >>7; // h will be 1 if the most significant bit of cWord[i] is set, 0 otherwise
            wordByTwo[i] = cWord[i] <<1;
            if (h==1) {
                wordByTwo[i] ^= 0x11B; // Multiplication in Rijndael's Galois field implemented via a left bit shift
                                    // and conditional xor with 0x11B (if leftmost bit of original byte was set)
                                    // 0x11B corresponds to the irreducible quadratic x^8 + x^4 + x^3 + x + 1
            }
        }
        // wordByTwo[i] xor cWord[i] is cWord[i] multiplied by 3 in Rijndael's Galois field
        // ref. http://www.angelfire.com/biz7/atleast/mix_columns.pdf
        // see equation 5.6 on pg. 18 of NIST AES specification
        outWord[0] = wordByTwo[0] ^ (wordByTwo[1] ^ cWord[1]) ^ cWord[2] ^ cWord[3]; // ({02}*w[0]) + ({03}*w[1]) + w[2] + w[3]
        outWord[1] = cWord[0] ^ wordByTwo[1] ^ (wordByTwo[2] ^ cWord[2]) ^ cWord[3]; // w[0] + ({02}*w[1]) + ({03}*w[2]) + w[3]
        outWord[2] = cWord[0] ^ cWord[1] ^ wordByTwo[2] ^ (wordByTwo[3] ^ cWord[3]); // w[0] + w[1] + ({02}*w[2]) + ({03}*w[3])
        outWord[3] = (wordByTwo[0] ^ cWord[0]) ^ cWord[1] ^ cWord[2] ^ wordByTwo[3]; // ({03}^w[0]) + w[1] + w[2] + ({02}*w[3])
        return outWord;
    }

    /*
     * Adds a round key to the state by bitwise xor of the column words w/ key words
     * @params two dimensional array of integers w/ columns corresponding to the 32 bit key words
     */
    public static void addRoundKey(int[][] keyBlock) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateArray[j][i] ^= keyBlock[j][i];
            }
        }
    }

    /*
    ------------------------------------------
               Key Expansion Methods
    ------------------------------------------
     */

    /*
     * Applies the sbox to a four byte input word
     * @params initial 32 bit word in the form of an array of 4 integers
     * @return a 32 bit word in which each byte corresponds to the sbox output from the respective iWord byte
     */
    public static int[] subWord(int[] iWord) {
        int[] rWord = new int[4];
        for (int i = 0; i < 4; i++) {
            int x = iWord[i] / 16; // each byte is divided into nibbles which form the
            int y = iWord[i] % 16; // respective row and column indices for the sbox
            rWord[i] = sbox[x][y];
        }
        return rWord;
    }

    /*
     * Performs a cyclic permutation (shifts the bytes left) ref NIST AES specification pg. 19 sec 5.2
     * @params initial 32 bit word in the word of an array of 4 integers
     * @return a 32 bit word in which each byte is shifted to the left
     * Note: [a0, a1, a2, a3] ----> [a1, a2, a3, a0]
     */
    public static int[] rotWord(int[] iWord) {
        int[] rWord = new int[4];
        for (int i = 0; i < 4; i ++) {
            int x = (i + 1) == 4 ? 0 : i + 1;
            rWord[i] = iWord[x];
        }
        return rWord;
    }

    /*
     * The Key Expansion method, creates the round keys
     */
    public static void keyExpansion() {
        readKeyData();

    }

    /*

    /*
     * Generates a round constant for the key expansion algorithm
     * @params i, the round for which the round constant is needed
     * @return a 32 bit word which corresponds to the round constant for the ith round

    public static int[] rCon(int i) {
        // https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
        // https://crypto.stackexchange.com/questions/2418/how-to-use-rcon-in-key-expansion-of-128-bit-advanced-encryption-standard
        // Note: There are also tables available for this purpose
        // Maybe this doesn't need to be it's own separate function, should be implemented in key exp method
    }

    */

}
