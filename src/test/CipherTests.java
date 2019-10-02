/*
 * Author: Spencer Little
 * Date: 08/29/2019
 * A set of unit tests for the various functions of the AES cipher
 */
package test;

import cipher.AES;
import org.junit.Test;
import org.junit.Assert;

/**
 * Unit tests for the AES encryption/decryption and CBC mode
 * @author Spencer Little
 * @version 1.0.0
 */
public class CipherTests {

    @Test
    public void testCipherEncryption() {
        AES crypt = new AES();
        int[][] initKey = { // Values lifted from example provided in NIST AES Specification Appendix B pg. 33
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        int[][] initState = {
                {0x32, 0x88, 0x31, 0xe0},
                {0x43, 0x5a, 0x31, 0x37},
                {0xf6, 0x30, 0x98, 0x07},
                {0xa8, 0x8d, 0xa2, 0x34}};
        int[][] resultState = {
                {0x39, 0x02, 0xdc, 0x19},
                {0x25, 0xdc, 0x11, 0x6a},
                {0x84, 0x09, 0x85, 0x0b},
                {0x1d, 0xfb, 0x97, 0x32}};

        crypt.keySize = 4;
        crypt.initializeRoundKeys(initKey);
        crypt.setState(initState);
        crypt.keyExpansion();
        crypt.cipher();

        Assert.assertArrayEquals(resultState, crypt.getStateArray());
    }

    @Test
    public void testCipherDecryption() {
        AES crypt = new AES();
        int[][] initKey = {
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        int[][] initState = {
                {0x39, 0x02, 0xdc, 0x19},
                {0x25, 0xdc, 0x11, 0x6a},
                {0x84, 0x09, 0x85, 0x0b},
                {0x1d, 0xfb, 0x97, 0x32}};

        crypt.initializeRoundKeys(initKey);
        crypt.setState(initState);
        crypt.keyExpansion();
        crypt.cipher();
        crypt.invCipher();

        Assert.assertArrayEquals(initState, crypt.getStateArray());
    }

    /*
     * Test vector lifted from NIST SP 800-38A (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
     */
    @Test
    public void testCBCModeCompliance() {
        AES crypt = new AES();
        int[][] initKey = {
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        int[][] iv = {
                {0x00, 0x01, 0x02, 0x03},
                {0x04, 0x05, 0x06, 0x07},
                {0x08, 0x09, 0x0a, 0x0b},
                {0x0c, 0x0d, 0x0e, 0x0f}};
        int[][] plainTextOne = {
                {0x6b, 0xc1, 0xbe, 0xe2},
                {0x2e, 0x40, 0x9f, 0x96},
                {0xe9, 0x3d, 0x7e, 0x11},
                {0x73, 0x93, 0x17, 0x2a}};
        int[][] outputOne = {
                {0x76, 0x49, 0xab, 0xac},
                {0x81, 0x19, 0xb2, 0x46},
                {0xce, 0xe9, 0x8e, 0x9b},
                {0x12, 0xe9, 0x19, 0x7d}};
        int[][] plainTextTwo = {
                {0xae, 0x2d, 0x8a, 0x57},
                {0x1e, 0x03, 0xac, 0x9c},
                {0x9e, 0xb7, 0x6f, 0xac},
                {0x45, 0xaf, 0x8e, 0x51}};
        int[][] outputTwo = {
                {0x50, 0x86, 0xcb, 0x9b},
                {0x50, 0x72, 0x19, 0xee},
                {0x95, 0xdb, 0x11, 0x3a},
                {0x91, 0x76, 0x78, 0xb2}};

        crypt.setState(rowsToColumns(plainTextOne));
        crypt.initializeRoundKeys(initKey);
        
        crypt.keyExpansion();
        crypt.setInitializationVector(rowsToColumns(iv));

        crypt.xorVectorWithState(); // xor the IV, or the previous ciphertext block with the state
        crypt.cipher();

        Assert.assertArrayEquals(crypt.getStateArray(), rowsToColumns(outputOne));

        crypt.setInitializationVector(crypt.getStateArray());
        crypt.setState(rowsToColumns(plainTextTwo));
        crypt.xorVectorWithState();
        crypt.cipher();

        Assert.assertArrayEquals(crypt.getStateArray(), rowsToColumns(outputTwo));
    }

    /*
     * Turns the rows of the matrix into the columns
     */
    private int[][] rowsToColumns(int[][] inp) {
        int[][] asWord = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                asWord[j][i] = inp[i][j];
            }
        }
        return asWord;
    }

}

