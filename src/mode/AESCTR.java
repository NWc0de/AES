package mode;

import cipher.AES;

public class AESCTR extends AES {

    private byte[] inputBlocks;
    private int[][] counterBlock;

    public AESCTR(byte[] inputBlocks, int[] keyBytes, int[][] counterBlock) {
        boolean isICBValidDim = counterBlock.length == 4;
        boolean isKeyLengthValid = keyBytes.length == 16 || keyBytes.length == 24 || keyBytes.length == 32;
        for (int i = 0; i < 4; i++) {
            isICBValidDim = isICBValidDim && (counterBlock[i].length == 4);
        }
        if (!isICBValidDim) {
            throw new IllegalArgumentException("Initial Counter block ");
        }
        if (!isKeyLengthValid) {
            throw new IllegalArgumentException("Key length must be 128, 192, or 256 bits.");
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

    public byte[] counterModeCipher(boolean encrypt) {
        int blockLen = encrypt ? ((inputBlocks.length/16) + 1) * 16 : 
        byte[] cipherBlocks = new byte[((inputBlocks.length/16) + 1) * 16]; // add an extra block for padding
        for (int i = 0; i < (inputBlocks.length/16) + 1; i++) {
            processBlock(cipherBlocks, inputBlocks, i, encrypt);
        }
        return cipherBlocks;
    }

    /*
     * Processes a block of plaintext based on offset, pads w/ PKCS#7 if bytes are insufficient
     */
    private void processBlock(byte[] output, byte[] input, int offset, boolean encrypt) {
        byte[] block = new byte[16];
        int finalBytePos = Math.min(input.length, (offset * 16) + 16);
        int toPad = ((offset*16) + 16) - input.length;
        System.arraycopy(input, offset*16, block, 0, finalBytePos - (offset*16));
        if (finalBytePos==input.length) {
            writeFinalBlock(output, block, offset, toPad, encrypt);
        } else {
            this.stateArray = counterBlock;
            this.cipher();
            this.writeBlockToByteArray(output, xorBlocks(stateAsBytes(), block), offset);
            this.incrementCB();
        }
    }

    private byte[] xorBlocks(byte[] blockOne, byte[] blockTwo) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) (blockOne[i] ^ blockTwo[i]);
        }
        return out;
    }

    private byte[] stateAsBytes() {
        byte[] state = new byte[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j + (i*4)] = (byte) stateArray[j][i];
            }
        }
        return state;
    }

    private void writeBlockToByteArray(byte[] output, byte[] block, int offset) {
        for (int i = 0; i < 16; i++) {
            output[i + (offset*16)] = block[i];
        }
    }

    private void writeFinalBlock(byte[] output, byte[] block, int offset, int toPad, boolean encrypt) {
        if (toPad==0 && encrypt) {
            this.stateArray = counterBlock;
            this.cipher();
            this.writeBlockToByteArray(output, xorBlocks(stateAsBytes(), block), offset);
            toPad = 16;
            this.incrementCB();
        }
        if (encrypt) {
            int padded = 0;
            while (padded < toPad) {
                block[15 - padded] = (byte) toPad;
                padded++;
            }
            this.stateArray = counterBlock;
            this.cipher();
            this.writeBlockToByteArray(output, xorBlocks(stateAsBytes(), block), offset);
        } else {
            this.stateArray = counterBlock;
            this.cipher();
            byte[] finalBlock = xorBlocks(stateAsBytes(), block);
            int toWrite = 16 - finalBlock[15];
            for (int i = 0; i < toWrite; i++) {
                output[i + (offset*16)] = finalBlock[i];
            }
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
        byte[] inp = new byte[] {0x04};
        int[] initKey = {0x2b, 0x7e, 0x15, 0x16,0x28, 0xae, 0xd2, 0xa6,0xab, 0xf7, 0x15, 0x88,0x09, 0xcf, 0x4f, 0x3c};
        int[] initKeyTwo = {0x8e, 0x73, 0xb0, 0xf7,0xda, 0x0e, 0x64, 0x52,0xc8, 0x10, 0xf3, 0x2b,0x80, 0x90, 0x79, 0xe5,0x62, 0xf8, 0xea, 0xd2,0x52, 0x2c, 0x6b, 0x7b};
        int[][] initCount = { // Values lifted from example provided in Cipher.AES Specification Appendix B pg. 33
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
        byte[] result = cnt.counterModeCipher(true);
        System.out.println("Encrypted");
        for (byte b : result) {
            System.out.print(b + ",");
        }
        System.out.println();

        System.out.println("Decrypted");
        AESCTR cntTwo = new AESCTR(result, initKeyTwo, initCount);
        byte[] newResult = cntTwo.counterModeCipher(false);
        for (byte b : newResult) {
            System.out.print(b + ",");
        }
    }
}
