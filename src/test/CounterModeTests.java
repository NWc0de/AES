/**
 * Author: Spencer Little
 * Date: 09/11/2019
 * A set of unit tests for the CTR mode functions of AES
 */
package test;

import cipher.AES;
import org.junit.Assert;
import org.junit.Test;
import mode.AESCTR;

public class CounterModeTests {

    @Test
    public void testCounterModeCipher() {
        byte[] initialData = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0x72, 0x0a, 0x13, 0x54, 0x53, 0x55, 0x36, 0x10, 0x11, 0x4f, 0x3c,
                              0x76, 0x7c, 0x15, 0x16, 0x32, 0x78, 0x0b, 0x18, 0x54, 0x17, 0x15, 0x32, 0x09, 0x4e, 0x4f, 0x4f};
        byte[] initialDataOne = {0x0e, 0x73, 0x32, 0x0e, 0x0a, 0x0e, 0x64, 0x52, 0x0c, 0x10, 0x15, 0x2b, 0x32, 0x18, 0x79, 0x0b,
                                 0x2b, 0x7e, 0x15, 0x16, 0x28, 0x72, 0x0a, 0x13, 0x54, 0x53, 0x55, 0x36, 0x10, 0x11, 0x4f, 0x3c,
                                 0x76, 0x7c, 0x15, 0x16, 0x32, 0x78, 0x0b, 0x18, 0x54, 0x17, 0x15, 0x32, 0x09, 0x4e, 0x4f, 0x4f,
                                 0x62, 0x74, 0x77, 0x09, 0x52, 0x2c, 0x6b, 0x7b,  0x16, 0x32, 0x78, 0x0b, 0x18, 0x54, 0x17, 0x0e};
        int[] initKey = {0x2b, 0x7e, 0x15, 0x16,0x28, 0xae, 0xd2, 0xa6,0xab, 0xf7, 0x15, 0x88,0x09, 0xcf, 0x4f, 0x3c};
        int[] initKeyOne = {0x8e, 0x73, 0xb0, 0xf7,0xda, 0x0e, 0x64, 0x52,0xc8, 0x10, 0xf3, 0x2b,0x80, 0x90, 0x79, 0xe5,0x62, 0xf8, 0xea, 0xd2,0x52, 0x2c, 0x6b, 0x7b};
        int[][] initCount = {
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};

        AESCTR crypt = new AESCTR(initialData, initKey, deepCopy(initCount)); // deepCopy to avoid mutability issues
        byte[] encrypted = crypt.counterModeCipher();

        crypt.setInternalState(encrypted, initKey, deepCopy(initCount));
        byte[] decrypted = crypt.counterModeCipher();

        crypt.setInternalState(initialDataOne, initKeyOne, deepCopy(initCount));
        byte[] encryptedOne = crypt.counterModeCipher();

        crypt.setInternalState(encryptedOne, initKeyOne, deepCopy(initCount));
        byte[] decryptedOne = crypt.counterModeCipher();

        Assert.assertArrayEquals(decrypted, initialData);
        Assert.assertArrayEquals(decryptedOne, initialDataOne);
    }

    /*
     * Test vector lifted from NIST SP 800-38A (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
     */
    @Test
    public void testCounterModeCompliance() {
        AES crypt = new AES();
        int[][] initKey = {
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        int[][] initialCounter = {
                {0xf0,0xf1,0xf2,0xf3},
                {0xf4,0xf5,0xf6,0xf7},
                {0xf8,0xf9,0xfa,0xfb},
                {0xfc,0xfd,0xfe,0xff}};
        int[][] plainTextOne = {
                {0x6b, 0xc1, 0xbe, 0xe2},
                {0x2e, 0x40, 0x9f, 0x96},
                {0xe9, 0x3d, 0x7e, 0x11},
                {0x73, 0x93, 0x17, 0x2a}};
        int[][] plainTextTwo = {
                {0xae, 0x2d, 0x8a, 0x57},
                {0x1e, 0x03, 0xac, 0x9c},
                {0x9e, 0xb7, 0x6f, 0xac},
                {0x45, 0xaf, 0x8e, 0x51}};
        int[][] output = {
                {0x87,0x4d,0x61,0x91},
                {0xb6,0x20,0xe3,0x26},
                {0x1b,0xef,0x68,0x64},
                {0x99,0x0d,0xb6,0xce}};
        int[][] outputTwo = {
                {0x98,0x06,0xf6,0x6b},
                {0x79,0x70,0xfd,0xff},
                {0x86,0x17,0x18,0x7b},
                {0xb9,0xff,0xfd,0xff}};

        crypt.setState(rowsToColumns(initialCounter));

        crypt.initializeRoundKeys(initKey);

        crypt.keyExpansion();
        crypt.cipher(); // since we are testing CTR mode the state is actually IV
        crypt.setInitializationVector(deepCopy(crypt.getStateArray()));
        crypt.setState(rowsToColumns(plainTextOne));
        crypt.xorVectorWithState();

        Assert.assertArrayEquals(crypt.getStateArray(), rowsToColumns(output));

        initialCounter[3][2] = 0xff;
        initialCounter[3][3] = 0x00;
        crypt.setState(rowsToColumns(initialCounter));
        crypt.cipher();
        crypt.setInitializationVector(deepCopy(crypt.getStateArray()));
        crypt.setState(rowsToColumns(plainTextTwo));
        crypt.xorVectorWithState();

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

    private int[][] deepCopy(int[][] original ) {
        int[][] result = new int[original.length][original[0].length]; // assumes dimensions are square
        for (int i = 0; i < original.length; i++) {
            System.arraycopy(original[i], 0, result[i], 0, original[i].length);
        }
        return result;
    }
}
