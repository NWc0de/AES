package mode;

import cipher.AES;

public class AESCTR extends AES {

    private byte[] inputBlocks;

    public AESCTR(byte[] inputBlocks, int[] keyBytes, int[][] initCounterBlock) {
        this.inputBlocks = inputBlocks;
    }
}
