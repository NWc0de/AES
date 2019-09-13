/**
 * Author: Spencer Little
 * Date: 08/29/2019
 * A set of unit tests for the various functions of the AES cipher
 */
package test;

import cipher.AES;
import org.junit.Test;
import org.junit.Assert;

public class CipherTests {

    @Test
    public void testShiftRows() {
        AES crypt = new AES();
        int[][] unShifted =  {
                {0,1,2,3},
                {0,1,2,3},
                {0,1,2,3},
                {0,1,2,3}};

        int[][] shifted =  {
                {0,1,2,3},
                {1,2,3,0}, // shifted left by one byte
                {2,3,0,1}, // shifted left by two bytes
                {3,0,1,2}}; // shifted left by three bytes

        crypt.stateArray = unShifted;
        crypt.shiftRows(false);

        Assert.assertArrayEquals(crypt.stateArray, shifted);
    }

    @Test
    public void testColumnMix() {
        AES crypt = new AES();
        int[] initWord = {45, 38, 49, 76};
        int[] resultWord = {77, 126, 189, 248};
        int[] initWordTwo = {212, 191, 93, 48}; // source http://www.angelfire.com/biz7/atleast/mix_columns.pdf
        int[] resultWordTwo = {4, 102, 129, 229};
        int[] initWordThree = {242, 10, 34, 92}; // source Wikipedia AES Mix Columns page
        int[] resultWordThree = {159, 220, 88, 157};
        int[] initWordFour = {219, 19, 83, 69};
        int[] resultWordFour = {142, 77, 161, 188};
        int[] initWordFive = {1, 1, 1, 1};
        int[] resultWordFive = {1, 1, 1, 1};
        int[] initWordSix = {212, 212, 212, 213};
        int[] resultWordSix = {213, 213, 215, 214};

        Assert.assertArrayEquals(resultWord, crypt.mixColumnWord(initWord, false));
        Assert.assertArrayEquals(initWord, crypt.mixColumnWord(resultWord, true));
        Assert.assertArrayEquals(resultWordTwo, crypt.mixColumnWord(initWordTwo, false));
        Assert.assertArrayEquals(initWordTwo, crypt.mixColumnWord(resultWordTwo, true));
        Assert.assertArrayEquals(resultWordThree, crypt.mixColumnWord(initWordThree, false));
        Assert.assertArrayEquals(initWordThree, crypt.mixColumnWord(resultWordThree, true));
        Assert.assertArrayEquals(resultWordFour, crypt.mixColumnWord(initWordFour, false));
        Assert.assertArrayEquals(initWordFour, crypt.mixColumnWord(resultWordFour, true));
        Assert.assertArrayEquals(resultWordFive, crypt.mixColumnWord(initWordFive, false));
        Assert.assertArrayEquals(initWordFive, crypt.mixColumnWord(resultWordFive, true));
        Assert.assertArrayEquals(resultWordSix, crypt.mixColumnWord(initWordSix, false));
        Assert.assertArrayEquals(initWordSix, crypt.mixColumnWord(resultWordSix, true));
    }

    @Test
    public void testRoundConstant() {
        AES crypt = new AES();
        int[] initCon = {0x01, 0, 0, 0}; // Examples lifted from NIST AES specification Appendix A pg. 27
        int[] rConAtTwo = {0x02, 0, 0, 0};
        int[] rConAtThree = {0x04, 0, 0, 0};
        int[] rConAtFour = {0x08, 0, 0, 0};
        int[] rConAtFive = {0x10, 0, 0, 0};
        int[] rConAtSix = {0x20, 0, 0, 0};

        Assert.assertArrayEquals(initCon, crypt.getNextRCon(1)); // Note: Since the rCon function operates by cumulatively
        Assert.assertArrayEquals(rConAtTwo, crypt.getNextRCon(2)); // multiplying a class field the i parameter has no
        Assert.assertArrayEquals(rConAtThree, crypt.getNextRCon(3)); // consequence after the initial value, it is simply
        Assert.assertArrayEquals(rConAtFour, crypt.getNextRCon(4)); // to signify that we are not requesting the initial
        Assert.assertArrayEquals(rConAtFive, crypt.getNextRCon(5)); // constant and that a multiplication should be performed
        Assert.assertArrayEquals(rConAtSix, crypt.getNextRCon(6));
    }

    @Test
    public void testRotWord() {
        AES crypt = new AES();
        int[] initWord = {1, 2, 3, 4};
        int[] resultWord = {2, 3, 4, 1};

        Assert.assertArrayEquals(resultWord, crypt.rotWord(initWord));
    }

    @Test
    public void testKeyExpansion() {
        AES cryptOne = new AES();
        AES cryptTwo = new AES();
        AES cryptThree = new AES();
        int[][] initKey = { // Values lifted from example provided in AES Specification Appendix A pg. 27
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        int[][] initKeyTwo = {
                {0x8e, 0x73, 0xb0, 0xf7},
                {0xda, 0x0e, 0x64, 0x52},
                {0xc8, 0x10, 0xf3, 0x2b},
                {0x80, 0x90, 0x79, 0xe5},
                {0x62, 0xf8, 0xea, 0xd2},
                {0x52, 0x2c, 0x6b, 0x7b}};
        int[][] initKeyThree = {
                {0x60, 0x3d, 0xeb, 0x10},
                {0x15, 0xca, 0x71, 0xbe},
                {0x2b, 0x73, 0xae, 0xf0},
                {0x85, 0x7d, 0x77, 0x81},
                {0x1f, 0x35, 0x2c, 0x07},
                {0x3b, 0x61, 0x08, 0xd7},
                {0x2d, 0x98, 0x10, 0xa3},
                {0x09, 0x14, 0xdf, 0xf4}};

        // 128-bit key
        int[] roundFour = {0xa0, 0xfa, 0xfe, 0x17};
        int[] roundTen = {0x59, 0x35, 0x80, 0x7a};
        int[] roundTwentyThree = {0x11, 0xf9, 0x15, 0xbc};
        int[] roundFourtyThree = {0xb6, 0x63, 0x0c, 0xa6};
        cryptOne.keySize = 4;
        cryptOne.roundKeys = new int[4][44];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                cryptOne.roundKeys[i][j] = initKey[j][i];
            }
        }
        cryptOne.keyExpansion();
        Assert.assertArrayEquals(roundFour, cryptOne.getRoundKeyWordAt(4));
        Assert.assertArrayEquals(roundTen, cryptOne.getRoundKeyWordAt(10));
        Assert.assertArrayEquals(roundTwentyThree, cryptOne.getRoundKeyWordAt(23));
        Assert.assertArrayEquals(roundFourtyThree, cryptOne.getRoundKeyWordAt(43));

        // 192-bit key
        roundTen = new int[]{0x0e, 0x7a, 0x95, 0xb9};
        roundTwentyThree = new int[]{0x11, 0x3b, 0x30, 0xe6};
        roundFourtyThree = new int[]{0xad, 0x07, 0xd7, 0x53};
        int[] roundFiftyOne = {0x01, 0x00, 0x22, 0x02};
        cryptTwo.keySize = 6;
        cryptTwo.roundKeys = new int[4][52];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 6; j++) {
                cryptTwo.roundKeys[i][j] = initKeyTwo[j][i];
            }
        }
        cryptTwo.keyExpansion();
        Assert.assertArrayEquals(roundTen, cryptTwo.getRoundKeyWordAt(10));
        Assert.assertArrayEquals(roundTwentyThree, cryptTwo.getRoundKeyWordAt(23));
        Assert.assertArrayEquals(roundFourtyThree, cryptTwo.getRoundKeyWordAt(43));
        Assert.assertArrayEquals(roundFiftyOne, cryptTwo.getRoundKeyWordAt(51));

        // 256-bit key
        roundTwentyThree = new int[]{0x2f, 0x6c, 0x79, 0xb3};
        roundFourtyThree = new int[]{0x96, 0x74, 0xee, 0x15};
        roundFiftyOne = new int[]{0x74, 0x01, 0x90, 0x5a};
        int[] roundFiftyNine = {0x70, 0x6c, 0x63, 0x1e};
        cryptThree.keySize = 8;
        cryptThree.roundKeys = new int[4][60];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                cryptThree.roundKeys[i][j] = initKeyThree[j][i];
            }
        }
        cryptThree.keyExpansion();
        Assert.assertArrayEquals(roundTwentyThree, cryptThree.getRoundKeyWordAt(23));
        Assert.assertArrayEquals(roundFourtyThree, cryptThree.getRoundKeyWordAt(43));
        Assert.assertArrayEquals(roundFiftyOne, cryptThree.getRoundKeyWordAt(51));
        Assert.assertArrayEquals(roundFiftyNine, cryptThree.getRoundKeyWordAt(59));
    }

    @Test
    public void testCipherEncryption() {
        AES crypt = new AES();
        int[][] initKey = { // Values lifted from example provided in AES Specification Appendix B pg. 33
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
        crypt.roundKeys = new int[4][44];
        crypt.stateArray = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                crypt.roundKeys[i][j] = initKey[j][i];
                crypt.stateArray[i][j] = initState[i][j];
            }
        }
        crypt.keyExpansion();
        crypt.cipher();

        Assert.assertArrayEquals(resultState, crypt.stateArray);
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

        crypt.keySize = 4;
        crypt.roundKeys = new int[4][44];
        crypt.stateArray = new int[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                crypt.roundKeys[j][i] = initKey[j][i];
                crypt.stateArray[i][j] = initState[i][j];
            }
        }
        crypt.keyExpansion();
        crypt.cipher();
        crypt.invCipher();

        Assert.assertArrayEquals(initState, crypt.stateArray);
    }

    @Test
    public void testInvShiftRows() {
        AES crypt = new AES();
        int[][] unShifted =  {
                {0,1,2,3},
                {0,1,2,3},
                {0,1,2,3},
                {0,1,2,3}};

        int[][] shifted =  {
                {0,1,2,3},
                {3,0,1,2}, // shifted right by one byte
                {2,3,0,1}, // shifted right by two bytes
                {1,2,3,0}}; // shifted right by three bytes

        crypt.stateArray = unShifted;
        crypt.shiftRows(true);

        Assert.assertArrayEquals(crypt.stateArray, shifted);
    }

    @Test
    public void testGaloisMult() {
        AES crypt = new AES();
        Assert.assertEquals(0x23, crypt.galoisMult(7, 13));
        Assert.assertEquals(0x5c, crypt.galoisMult(12, 13));
        Assert.assertEquals(0x48, crypt.galoisMult(14, 12));
        Assert.assertEquals(0x27, crypt.galoisMult(5, 11));
        Assert.assertEquals(0x77, crypt.galoisMult(9, 15));
        Assert.assertEquals(0x26, crypt.galoisMult(2, 19));
        Assert.assertEquals(0x31, crypt.galoisMult(7, 11));
    }

    @Test
    public void testPadding() {
        int[][] stateArray = {
                {37,45,10,242},
                {80,49,37,229},
                {68,46,196,235},
                {70,51,229,167}};
        int[][] nineBytesPadded = {
                {255,255,9,9},
                {255,255,9,9},
                {255,255,9,9},
                {255,9,9,9}};
        int[][] elevenBytesWritten = {
                {101,101,101,9},
                {101,101,101,9},
                {101,101,101,9},
                {101,101,9,9}};

        // Method from applyPadding()
        int toPad = 9;
        int toRead = 7;
        int i = 0, j = 0, padded = 0;
        while (toRead > 0|| padded < toPad) {
            if (toRead > 0) {
                stateArray[j][i] = 255;
            }
            if (padded < toPad) {
                stateArray[3 - j][3 - i] = toPad;
                padded++;
            }
            toRead--;
            j++;
            if (j == 4) {i++; j = 0;}
        }
        Assert.assertArrayEquals(stateArray, nineBytesPadded);

        // Method from toWrite()
        int toWrite = 11;
        i = 0; j = 0;
        while (toWrite > 0) {
            stateArray[j][i] = 101;
            toWrite--;
            j++;
            if (j == 4) {i++; j = 0;}
        }
        Assert.assertArrayEquals(stateArray, elevenBytesWritten);
    }


}

