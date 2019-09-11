/**
 * Author: Spencer Little
 * Date: 09/11/2019
 * The GHASH function for AES-GCM (ref. https://csrc.nist.gov/publications/detail/sp/800-38d/final)
 */
package mode;

import cipher.AES;

public class GHASH {

    private static final int AES_BLOCK_LEN = 16;
    private static final int P128 = 0xe1;

    // Method credit: https://github.com/karianna/jdk8_tl/blob/master/jdk/src/share/classes/com/sun/crypto/provider/GHASH.java

    private static boolean getBit(byte[] byteStream, int bitPos) {
        int bytePos = bitPos / 8;
        bitPos %= 8;
        int i = (byteStream[bytePos] >>> (7-bitPos)) & 1; // isn't thing big endian?
        return i != 0;
    }

    private static void shift(byte[] byteStream) {
        byte temp, temp2;
        temp2 = 0;
        for (int i = 0; i < byteStream.length; i++) {
            temp = (byte) ((byteStream[i] & 0x01) << 7);
            byteStream[i] = (byte) ((byteStream[i] & 0xff) >>> 1);
            byteStream[i] = (byte) (byteStream[i] | temp2); // OR current byte with ( LSB of last byte << 7 )
            temp2 = temp;
        }
    }

    private static byte[] blockMult(byte[] x, byte[] y) {
        if (x.length != AES_BLOCK_LEN || y.length != AES_BLOCK_LEN) {
            throw new RuntimeException("Inappropriate block lengths (must be 16 bytes).");
        }
        // ref NIST SP 800-38D pg. 11-12 sec. 6.3
        byte[] z = new byte[AES_BLOCK_LEN];
        byte[] v = y.clone();
        for (int i = 0; i < 127; i++) {
            if (getBit(x, i)) {
                for (int j = 0; j < z.length; j++) {
                    z[j] ^= v[j];
                }
            }
            boolean lastBitOfV = getBit(v, 127);
            shift(v);
            if (lastBitOfV) v[0] ^= P128;
        }
        if (getBit(x, 127)) {
            for (int n = 0; n < z.length; n++) { // compute final z
                z[n] ^= v[n];
            }
        }
        return z;
    }






}
