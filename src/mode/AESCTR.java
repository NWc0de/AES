package mode;

import cipher.AES;

public class AESCTR extends AES {

    private byte[] inputBlocks;
    private int[][] counterBlock;

    public AESCTR(byte[] inputBlocks, int[] keyBytes, int[][] counterBlock) {
        setState(inputBlocks, keyBytes, counterBlock);
    }

    public void setState(byte[] inputBlocks, int[] keyBytes, int[][] counterBlock) {
        boolean isICBValidDim = counterBlock.length == 4;
        boolean isKeyLengthValid = keyBytes.length == 16 || keyBytes.length == 24 || keyBytes.length == 32;
        boolean isInputLengthValid = inputBlocks.length % 16 == 0;
        for (int i = 0; i < 4; i++) {
            isICBValidDim = isICBValidDim && (counterBlock[i].length == 4);
        }
        if (!isICBValidDim) {
            throw new IllegalArgumentException("Initial Counter block ");
        } else if (!isKeyLengthValid) {
            throw new IllegalArgumentException("Key length must be 128, 192, or 256 bits.");
        } else if (!isInputLengthValid) {
            throw new IllegalArgumentException("Input must conform to 16 byte block length");
        }
        this.inputBlocks = inputBlocks;
        this.counterBlock = counterBlock;
        this.keySize = keyBytes.length/4;
        this.roundCon = new int[]{0x01, 0, 0, 0};
        this.roundKeys = new int[4][4 * ((keySize)+7)];
        for (int i = 0; i < keySize; i++) {
            for (int j = 0; j < 4; j++) {
                this.roundKeys[j][i] = keyBytes[j + (i*4)];
            }
        }
        this.keyExpansion();
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

        this.stateArray = counterBlock;
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
            asLong += (long) (counterBlock[3][i] << (8 * (3-i)));
        }
        asLong = (asLong + 1) % 0x100000000L; // increment and reduce by 2^32
        for (int i = 3; i >= 0; i--) { // decompose long into bytes
            counterBlock[3][i] =  (int) (asLong & (0xff << (8 * (3-i)))) >>> (8* (3-i));
        }
    }
}
