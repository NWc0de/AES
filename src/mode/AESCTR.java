package mode;

import cipher.AES;

public class AESCTR extends AES {

    private byte[] inputBlocks;
    private int[][] counterBlock;

    public AESCTR(byte[] inputBlocks, int[] keyBytes, int[][] counterBlock) {
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
        System.arraycopy(input, offset*16, block, 0, (offset*16)+16);

        this.stateArray = counterBlock;
        this.cipher();
        this.writeBlockToByteArray(output, xorBlockWithState(block), offset);
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

    private void writeBlockToByteArray(byte[] output, byte[] block, int offset) {
        for (int i = 0; i < 16; i++) {
            output[i + (offset*16)] = block[i];
        }
    }

    private void incrementCB() {
        long asLong = 0;
        for (int i = 3; i >= 0; i--) { // convert final column word to long
            asLong += (long) (counterBlock[3][i] << (8 * (3-i)));
        }
        asLong = (asLong + 1) % 0x100000000L; // increment and reduce by 2^32
        for (int i = 3; i >= 0; i--) { // decompose long into bytes
            counterBlock[3][i] =  (int) (asLong & (0xff << (8 * (3-i)))) >>> (8* (3-i));
        }
    }

    public static void main(String[] args) {
        byte[] inp = {0x2b, 0x7e, 0x15, 0x16,0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,0x09, (byte) 0xcf, 0x4f, 0x3c};
        int[] initKey = {0x2b, 0x7e, 0x15, 0x16,0x28, 0xae, 0xd2, 0xa6,0xab, 0xf7, 0x15, 0x88,0x09, 0xcf, 0x4f, 0x3c};
        int[] initKeyTwo = {0x8e, 0x73, 0xb0, 0xf7,0xda, 0x0e, 0x64, 0x52,0xc8, 0x10, 0xf3, 0x2b,0x80, 0x90, 0x79, 0xe5,0x62, 0xf8, 0xea, 0xd2,0x52, 0x2c, 0x6b, 0x7b};
        int[][] initCount = { // Values lifted from example provided in Cipher.AES Specification Appendix B pg. 33
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        int[][] initCountTwo = { // Values lifted from example provided in Cipher.AES Specification Appendix B pg. 33
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        System.out.println("Initial");
        for (byte b : inp) {
            System.out.print(b + ",");
        }
        System.out.println();
        AESCTR cnt = new AESCTR(inp, initKeyTwo, initCount);
        byte[] result = cnt.counterModeCipher();
        System.out.println("Encrypted");
        for (byte b : result) {
            System.out.print(b + ",");
        }
        System.out.println();

        System.out.println("Decrypted");
        AESCTR cntTwo = new AESCTR(result, initKeyTwo, initCountTwo);
        byte[] newResult = cntTwo.counterModeCipher();
        for (byte b : newResult) {
            System.out.print(b + ",");
        }
    }
}
