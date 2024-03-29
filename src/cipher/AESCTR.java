/*
 * Author: Spencer Little
 * Date: 09/12/2019
 * Counter mode for the AES cipher (ref. https://csrc.nist.gov/publications/detail/sp/800-38d/final)
 */
package cipher;

/**
 * Implementation CTR mode via the AES class
 * @author Spencer Little
 * @version 1.0.0
 */
public class AESCTR extends AES {

    private byte[] inputBlocks;
    private int[][] currentCounter;

    /**
     * Initializes the cipher object with user data, calls {@code setInternalState()}
     * @see #setInternalState(byte[], int[][], int[][])
     */
    public AESCTR(byte[] inputBlocks, int[][] keyBytes, int[][] counterBlock) {
        super();
        setInternalState(inputBlocks, keyBytes, counterBlock);
    }

    /**
     * Sets the round keys, counter block, and input data (performs key expansion)
     * @param inputBlocks array of bytes to be ciphered (must conform to 16 byte block size)
     * @param keyBytes initial key bytes (integer array of dimensions 4 x 4, 6 x 4, or 8 x 4)
     * @param counterBlock initial counter block (integer array of dimension 4 x 4)
     */
    public void setInternalState(byte[] inputBlocks, int[][] keyBytes, int[][] counterBlock) {
        super.setState(counterBlock);
        super.initializeRoundKeys(keyBytes);
        boolean isInputLengthValid = inputBlocks.length % 16 == 0;
        if (!isInputLengthValid) {
            throw new IllegalArgumentException("Input must conform to 16 byte block length.");
        }
        this.inputBlocks = inputBlocks;
        this.setInitialCounter(counterBlock);
        this.keyExpansion();
    }

    /**
     * Sets the initial counter block
     * @param counterBlock (must be integer array of dimension 4 x 4)
     */
    public void setInitialCounter(int[][] counterBlock) {
        boolean isRowCountValid = counterBlock.length == 4;
        boolean isColumnCountValid = true;
        for (int[] intRow : counterBlock) {
            isColumnCountValid = isColumnCountValid && intRow.length == 4;
        }
        if (!(isRowCountValid && isColumnCountValid)) {
            throw new IllegalArgumentException("Initial counter block must be integer array of dimension 4 x 4.");
        }
        this.currentCounter = counterBlock;
    }

    /*
    ------------------------------------------
                    Cipher Methods
    ------------------------------------------
     */

    /**
     * Performs the cipher operation based on the object state
     * @return array of bytes corresponding to encrypted inputBlocks
     */
    public byte[] counterModeCipher() {
        byte[] cipherBlocks = new byte[inputBlocks.length];
        for (int i = 0; i < (inputBlocks.length/16); i++) {
            processBlock(cipherBlocks, inputBlocks, i);
        }
        return cipherBlocks;
    }

    /*
     * Processes a block of plaintext based on offset
     */
    private void processBlock(byte[] output, byte[] input, int offset) {
        byte[] block = new byte[16];
        System.arraycopy(input, offset*16, block, 0, 16);
        this.stateArray = deepCopy(currentCounter);
        this.cipher();
        System.arraycopy(xorBlockWithState(block), 0, output, offset*16, 16);
        this.incrementCounter();
    }

    private byte[] xorBlockWithState(byte[] block) {
        byte[] out = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                out[j + (i*4)] = (byte) (stateArray[j][i] ^ block[j + (i*4)]);
            }
        }
        return out;
    }

    /*
     * Increment counter block (state) by interpreting last four bytes as long
     * ref. NIST SP 800-38D pg. 11 sec. 6.2
     * Note: Due to the fact that longs are always signed in Java this is not standard incrementation
     */
    private void incrementCounter() {
        long asLong = 0;
        for (int i = 3; i >= 0; i--) { // convert final column word into long
            asLong += (long) (currentCounter[3][i] << (8 * (3-i)));
        }
        asLong = (asLong + 1) % 0x100000000L; // increment and reduce by 2^32
        for (int i = 3; i >= 0; i--) { // decompose long into bytes
            currentCounter[3][i] =  (int) (asLong & (0xff << (8 * (3-i)))) >> (8* (3-i));
        }
    }

    /*
    ------------------------------------------
                    I/O Methods
    ------------------------------------------
     */

    /*
     * Apply PKCS#7 padding scheme
     */
    public static byte[] padByteArray(byte[] byteArray) {
        int toPad = byteArray.length % 16 == 0 ? 16 : byteArray.length % 16;
        int temp = 0;
        byte[] padded = new byte[byteArray.length + toPad];
        System.arraycopy(byteArray, 0, padded, 0, byteArray.length);
        while (temp < toPad) {
            padded[padded.length - temp - 1] = (byte) toPad;
            temp++;
        }
        return padded;
    }

    public static byte[] removePadding(byte[] byteArray) {
        int toRemove = byteArray[byteArray.length -1];
        byte[] newBytes = new byte[byteArray.length - toRemove];
        System.arraycopy(byteArray, 0, newBytes, 0, byteArray.length - toRemove);
        return newBytes;
    }

}
