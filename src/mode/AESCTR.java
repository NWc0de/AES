package mode;

import cipher.AES;

public class AESCTR extends AES {

    private byte[] inputBlocks;

    public AESCTR(byte[] inputBlocks, int[] keyBytes, int[][] counterBlock) {
        setInternalState(inputBlocks, keyBytes, counterBlock);
    }

    /*
     * Sets the round keys, counter block, and input dat
     */
    public void setInternalState(byte[] inputBlocks, int[] keyBytes, int[][] counterBlock) {
        super.setState(counterBlock);
        super.setKey(keyBytes);
        boolean isInputLengthValid = inputBlocks.length % 16 == 0;
        if (!isInputLengthValid) {
            throw new IllegalArgumentException("Input must conform to 16 byte block length.");
        }
        this.inputBlocks = inputBlocks;
        this.stateArray = counterBlock;
    }

    /*
     * Assumes input is even block length.
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
        this.cipher();
        System.arraycopy(xorBlockWithState(block), 0, output, offset*16, 16);
        this.incrementCB();
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

    private void incrementCB() {
        long asLong = 0;
        for (int i = 3; i >= 0; i--) { // convert final column word into long
            asLong += (long) (stateArray[3][i] << (8 * (3-i)));
        }
        asLong = (asLong + 1) % 0x100000000L; // increment and reduce by 2^32
        for (int i = 3; i >= 0; i--) { // decompose long into bytes
            stateArray[3][i] =  (int) (asLong & (0xff << (8 * (3-i)))) >>> (8* (3-i));
        }
    }
}
