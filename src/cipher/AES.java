/*
 * Author: Spencer Little (mrlittle@uw.edu)
 * Date: 08/28/18
 * An implementation of the AES (Rijndael) cipher
 * ref. https://www.nist.gov/publications/advanced-encryption-standard-aes
 */
package cipher;

/**
 * Implements the AES cipher methods and provides an API for encryption/decryption (conforms to NIST spec)
 * @author  Spencer Little
 * @version 1.0.0
 */
public class AES {

    protected int[][] stateArray = new int[4][4]; // The state (two dimensional array containing 128 bit block of input data)
    protected int[][] roundKeys;
    /** 4, 6, 8 depending on number of 32 bit words in the initial key */
    public int keySize;
    private int[] roundCon = {0x01, 0, 0, 0}; // Initial value of the round constant used for key expansion
    protected int[][] initializationVector = new int[4][4];

    private final int[][] sbox = {
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

    private final int[][] invSbox = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

    /*
    ------------------------------------------
                 Getters/Setters
    ------------------------------------------
     */

    /**
     * Sets the input state (assigns by reference, not copied)
     * @param inputState two dimensional array of bytes (integers) corresponding to block of data
     */
    public void setState(int[][] inputState) {
        boolean isInputLengthValid = inputState.length == 4;
        for (int i = 0; i < 4; i++) {
            isInputLengthValid = isInputLengthValid && (inputState[i].length == 4);
        }
        if (!isInputLengthValid) {
            throw new IllegalArgumentException("State must be 16 bytes (4x4 array)");
        }
        this.stateArray = inputState;
    }

    public int[][] getStateArray() {
        return stateArray;
    }

    public void initializeRoundKeys(int[][] initKey) {
        boolean isKeyInvalid = initKey.length > 8 || initKey.length <= 2 || initKey.length%2==1;
        boolean isKeyInBytes = true;
        for (int i = 0; i < initKey.length; i++) {
            isKeyInBytes = isKeyInBytes && initKey[i].length == 4;
        }
        if (isKeyInvalid || !isKeyInBytes) {
            throw new IllegalArgumentException("Invalid key length. Key must be provided as a n * 4 array when n corresponds to the number of 32 bit words in key.");
        }
        this.roundCon = new int[]{0x01, 0, 0, 0};
        this.keySize = initKey.length;
        this.roundKeys = new int[4][4 * ((keySize)+7)];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < keySize; j++) {
                this.roundKeys[i][j] = initKey[j][i];
            }
        }
    }

    public void setInitializationVector(int[][] initVector) {
        boolean isInitVectorDimValid = initVector.length == 4;
        for (int i = 0; i < initVector.length; i++) {
            isInitVectorDimValid = isInitVectorDimValid && initVector[i].length == 4;
        }
        if (!isInitVectorDimValid) {
            throw new IllegalArgumentException("Initialization vector must be provided as 4 x 4 array of integers.");
        }
        this.initializationVector = initVector;
    }

    protected int[][] getInitKeyBytes() {
        int[][] initKeyBytes = new int[keySize][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < keySize; j++) {
                initKeyBytes[j][i] = this.roundKeys[i][j];
            }
        }
        return initKeyBytes;
    }

    /*
    ------------------------------------------
                    Main Methods
    ------------------------------------------
     */

    /*
     * Performs the cipher operations on the state
     * ref. NIST AES specification pg. 15 fig 5
     */
    public void cipher() {
        int rounds = keySize + 6;
        addRoundKey(getRoundKeyWordsInRange(0, keySize-1));
        for (int i = 1; i < rounds; i++) {
            subBytes(false);
            shiftRows(false);
            mixColumns(false);
            addRoundKey(getRoundKeyWordsInRange(i*4, ((i+1)*4)-1));
        }
        subBytes(false);
        shiftRows(false);
        addRoundKey(getRoundKeyWordsInRange(rounds*4, ((rounds+1)*4)-1));
    }

    /*
     * Performs inverse cipher operations on the state
     * ref. NIST AES specification pg.21 fig 12
     */
    public void invCipher() {
        int rounds = keySize + 6;
        addRoundKey(getRoundKeyWordsInRange(rounds*4, ((rounds+1)*4)-1));
        for (int i = rounds-1; i > 0; i--) {
            shiftRows(true);
            subBytes(true);
            addRoundKey(getRoundKeyWordsInRange(i*4, ((i+1)*4)-1));
            mixColumns(true);
        }
        shiftRows(true);
        subBytes(true);
        addRoundKey(getRoundKeyWordsInRange(0, keySize-1));
    }

    /*
    ------------------------------------------
                    Cipher Methods
    ------------------------------------------
     */

    /*
     * Performs the byte substitution operation specified in the NIST standard (pg. 15 sec 5.1.1)
     */
    public void subBytes(boolean inverse) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int x = stateArray[i][j] / 16; // each byte is divided into nibbles which form the
                int y = stateArray[i][j] % 16; // respective row and column indices for the sbox
                stateArray[i][j] = inverse ? invSbox[x][y] : sbox[x][y];
            }
        }
    }

    /*
     * Shifts bytes in the last three rows (NIST AES specification pg. 17 sec 5.1.2/pg. 21 sec 5.3.1)
     * @params boolean inverse to indicate the direction of the shift
     */
    public void shiftRows(boolean inverse) {
        for (int i = 1; i < 4; i++) {
            int[] tempRow = new int[4];
            System.arraycopy(stateArray[i], 0, tempRow, 0,4);
            for (int j = 0; j < 4; j++) {
                int shiftInd = inverse ? (j - i + 4) % 4 : (j + i) % 4;
                stateArray[i][j] = tempRow[shiftInd];
            }
        }
    }

    /*
     * ref. NIST AES specification pg. 18 sec 5.1.3
     * Note: The column mixing operation assures the plaintext is sufficiently diffused
     */
    public void mixColumns(boolean inverse) {
        for (int i = 0; i < 4; i++) {
            int[] cWord = new int[4];
            for (int j = 0; j < 4; j++) {
                cWord[j] = stateArray[j][i];
            }
            cWord = mixColumnWord(cWord, inverse);
            for (int j = 0; j < 4; j++) {
                stateArray[j][i] = cWord[j];
            }
        }
    }

    /*
     * Performs the column mixing operations via Galois multiplication (ref. NIST AES sepcification eq 5.6 pg. 18/eq 5.10 pg. 23)
     * @params 32 bit word representing column of the state, boolean indicating which coefficients should be used
     * @return 32 bit word, the product of the multiplication operations
     */
    public int[] mixColumnWord(int[] cWord, boolean inverse) {
        int[] outWord = new int[4];
        int[] coef = inverse ? new int[]{0x0e, 0x0b, 0x0d, 0x09} : new int[]{0x02, 0x03, 0x01, 0x01};
        for (int i = 0; i < 4; i++) {
            int temp = 0;
            for (int j = 0; j < 4; j++) {
                temp ^= galoisMult(cWord[j], coef[(j - i + 4) % 4]);
            }
            outWord[i] = temp;
        }
        return outWord;
    }

    public void addRoundKey(int[][] keyBlock) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateArray[j][i] ^= keyBlock[j][i];
            }
        }
    }

    /*
     * Performs multiplication in GF(2^8) w/ the Russian Peasant multiplication algorithm
     */
    public int galoisMult(int a, int b) {
        int res = 0;
        while (a != 0 && b != 0) {
            if ((b & 1) == 1)
                res ^= a;
            if ((a & 0x80) != 0)
                a = (a <<1) ^ 0x11B;
            else
                a <<= 1;
            b >>>= 1;
        }
        return res;
    }

    public void xorVectorWithState() {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateArray[j][i] ^= initializationVector[j][i];
            }
        }
    }

    protected int[][] deepCopy(int[][] original) {
        int[][] result = new int[original.length][original[0].length]; // assumes square dimensions
        for (int i = 0; i < original.length; i++) {
            System.arraycopy(original[i], 0, result[i], 0, original[i].length);
        }
        return result;
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
    public int[] subWord(int[] iWord) {
        int[] rWord = new int[4];
        for (int i = 0; i < 4; i++) {
            int x = iWord[i] / 16;
            int y = iWord[i] % 16;
            rWord[i] = sbox[x][y];
        }
        return rWord;
    }

    /*
     * Performs a cyclic permutation (shifts the bytes left)
     * @params initial 32 bit word in the word of an array of 4 integers
     * @return a 32 bit word in which each byte is shifted to the left
     */
    public int[] rotWord(int[] iWord) {
        int[] rWord = new int[4];
        for (int i = 0; i < 4; i ++) {
            int x = (i + 1) == 4 ? 0 : i + 1;
            rWord[i] = iWord[x];
        }
        return rWord;
    }

    /*
     * The Key Expansion method, creates the round keys
     * ref. NIST AES specification pg. 20 fig. 11
     */
    public void keyExpansion() {
        int i = keySize;
        while (i < (4 * ((keySize)+7)) ) {
            int[] temp = getRoundKeyWordAt(i-1);
            if (i % (keySize) == 0) { // if i is a multiple of keySize a special transformation is applied before xoring
                temp = xorWords(subWord(rotWord(temp)), getNextRCon(i/(keySize)));
            } else if (keySize > 6 && i % keySize == 4) {
                temp = subWord(temp);
            }
            setRoundKeysAt(i, xorWords(getRoundKeyWordAt(i - keySize), temp));
            i++;
        }
    }

    public int[] getRoundKeyWordAt(int i) {
        int[] roundWord = new int[4];
        for (int j = 0; j < 4; j++) {
            roundWord[j] = roundKeys[j][i];
        }
        return roundWord;
    }

    public void setRoundKeysAt(int i, int[] word) {
        for (int j = 0; j < 4; j++) {
            roundKeys[j][i] = word[j];
        }
    }

    public int[] xorWords(int[] wordOne, int[] wordTwo) {
        int[] product = new int[4];
        for (int i = 0; i < 4; i++) {
            product[i] = wordOne[i] ^ wordTwo[i];
        }
        return product;
    }

    public int[][] getRoundKeyWordsInRange(int i, int j) {
        int[][] roundKeyBlock = new int[4][i+j+1];
        int currentWord = 0;
        for (int x = i; x <= j; x++) {
            int[] temp = getRoundKeyWordAt(x);
            for (int z = 0; z < 4; z++) {
                roundKeyBlock[z][currentWord] = temp[z];
            }
            currentWord++;
        }
        return roundKeyBlock;
    }

    /*
     * @params i, a flag indicating whether this is the first rCon (1), or not (!1)
     * @return a 32 bit word which corresponds to the required round constant
     * Because the round constants will never be needed out of order this method saves time and space
     */
    public int[] getNextRCon(int i) {
        // Return the initial value of rCon, or multiply previous value by 2 to compute next constant
        if (i == 1) {
            return roundCon;
        } else {
            roundCon = new int[]{galoisMult(roundCon[0], 2), 0, 0, 0};
            return roundCon;
        }
    }

}
