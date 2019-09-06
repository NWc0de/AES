/**
 * Author: Spencer Little
 * Date: 08/29/2019
 * A set of unit tests for the various functions of the AES cipher
 */

import org.junit.Test;
import org.junit.Assert;

public class CipherTests {

    @Test
    public void testShiftRows() {
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

        AES.stateArray = unShifted;
        AES.shiftRows(false);

        Assert.assertArrayEquals(AES.stateArray, shifted);
    }

    @Test
    public void testColumnMix() {
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

        Assert.assertArrayEquals(resultWord, AES.mixColumnWord(initWord, false));
        Assert.assertArrayEquals(initWord, AES.mixColumnWord(resultWord, true));
        Assert.assertArrayEquals(resultWordTwo, AES.mixColumnWord(initWordTwo, false));
        Assert.assertArrayEquals(initWordTwo, AES.mixColumnWord(resultWordTwo, true));
        Assert.assertArrayEquals(resultWordThree, AES.mixColumnWord(initWordThree, false));
        Assert.assertArrayEquals(initWordThree, AES.mixColumnWord(resultWordThree, true));
        Assert.assertArrayEquals(resultWordFour, AES.mixColumnWord(initWordFour, false));
        Assert.assertArrayEquals(initWordFour, AES.mixColumnWord(resultWordFour, true));
        Assert.assertArrayEquals(resultWordFive, AES.mixColumnWord(initWordFive, false));
        Assert.assertArrayEquals(initWordFive, AES.mixColumnWord(resultWordFive, true));
        Assert.assertArrayEquals(resultWordSix, AES.mixColumnWord(initWordSix, false));
        Assert.assertArrayEquals(initWordSix, AES.mixColumnWord(resultWordSix, true));
    }

    @Test
    public void testRoundConstant() {
        int[] initCon = {0x01, 0, 0, 0}; // Examples lifted from NIST AES specification Appendix A pg. 27
        int[] rConAtTwo = {0x02, 0, 0, 0};
        int[] rConAtThree = {0x04, 0, 0, 0};
        int[] rConAtFour = {0x08, 0, 0, 0};
        int[] rConAtFive = {0x10, 0, 0, 0};
        int[] rConAtSix = {0x20, 0, 0, 0};

        Assert.assertArrayEquals(initCon, AES.getNextRCon(1)); // Note: Since the rCon function operates by cumulatively
        Assert.assertArrayEquals(rConAtTwo, AES.getNextRCon(2)); // multiplying a class field the i parameter has no
        Assert.assertArrayEquals(rConAtThree, AES.getNextRCon(3)); // consequence after the initial value, it is simply
        Assert.assertArrayEquals(rConAtFour, AES.getNextRCon(4)); // to signify that we are not requesting the initial
        Assert.assertArrayEquals(rConAtFive, AES.getNextRCon(5)); // constant and that a multiplication should be performed
        Assert.assertArrayEquals(rConAtSix, AES.getNextRCon(6));

        AES.roundCon = new int[]{0x01, 0, 0, 0}; // Reset round constant to avoid interference with other tests
    }

    @Test
    public void testRotWord() {
        int[] initWord = {1, 2, 3, 4};
        int[] resultWord = {2, 3, 4, 1};

        Assert.assertArrayEquals(resultWord, AES.rotWord(initWord));
    }

    @Test
    public void testKeyExpansion() {
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
        AES.keySize = 4;
        AES.roundKeys = new int[4][44];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                AES.roundKeys[i][j] = initKey[j][i];
            }
        }
        AES.keyExpansion();
        Assert.assertArrayEquals(roundFour, AES.getRoundKeyWordAt(4));
        Assert.assertArrayEquals(roundTen, AES.getRoundKeyWordAt(10));
        Assert.assertArrayEquals(roundTwentyThree, AES.getRoundKeyWordAt(23));
        Assert.assertArrayEquals(roundFourtyThree, AES.getRoundKeyWordAt(43));

        AES.roundCon = new int[]{0x01, 0, 0, 0};

        // 192-bit key
        roundTen = new int[]{0x0e, 0x7a, 0x95, 0xb9};
        roundTwentyThree = new int[]{0x11, 0x3b, 0x30, 0xe6};
        roundFourtyThree = new int[]{0xad, 0x07, 0xd7, 0x53};
        int[] roundFiftyOne = {0x01, 0x00, 0x22, 0x02};
        AES.keySize = 6;
        AES.roundKeys = new int[4][52];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 6; j++) {
                AES.roundKeys[i][j] = initKeyTwo[j][i];
            }
        }
        AES.keyExpansion();
        Assert.assertArrayEquals(roundTen, AES.getRoundKeyWordAt(10));
        Assert.assertArrayEquals(roundTwentyThree, AES.getRoundKeyWordAt(23));
        Assert.assertArrayEquals(roundFourtyThree, AES.getRoundKeyWordAt(43));
        Assert.assertArrayEquals(roundFiftyOne, AES.getRoundKeyWordAt(51));

        AES.roundCon = new int[]{0x01, 0, 0, 0};

        // 256-bit key
        roundTwentyThree = new int[]{0x2f, 0x6c, 0x79, 0xb3};
        roundFourtyThree = new int[]{0x96, 0x74, 0xee, 0x15};
        roundFiftyOne = new int[]{0x74, 0x01, 0x90, 0x5a};
        int[] roundFiftyNine = {0x70, 0x6c, 0x63, 0x1e};
        AES.keySize = 8;
        AES.roundKeys = new int[4][60];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                AES.roundKeys[i][j] = initKeyThree[j][i];
            }
        }
        AES.keyExpansion();
        Assert.assertArrayEquals(roundTwentyThree, AES.getRoundKeyWordAt(23));
        Assert.assertArrayEquals(roundFourtyThree, AES.getRoundKeyWordAt(43));
        Assert.assertArrayEquals(roundFiftyOne, AES.getRoundKeyWordAt(51));
        Assert.assertArrayEquals(roundFiftyNine, AES.getRoundKeyWordAt(59));
    }

    @Test
    public void testCipherEncryption() {
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

        AES.keySize = 4;
        AES.roundKeys = new int[4][44];
        AES.stateArray = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                AES.roundKeys[i][j] = initKey[j][i];
                AES.stateArray[i][j] = initState[i][j];
            }
        }
        AES.keyExpansion();
        AES.cipher();

        Assert.assertArrayEquals(resultState, AES.stateArray);

        AES.roundCon = new int[]{0x01, 0, 0, 0};
    }

    @Test
    public void testCipherDecryption() {
        int[][] initKey = { // Values lifted from example provided in AES Specification Appendix B pg. 33
                {153, 10, 39, 222},
                {156, 180, 77, 119},
                {28, 109, 178, 247},
                {117, 163, 211, 139}};
        int[][] initState = {
                {16, 16, 16, 16},
                {16, 16, 16, 16},
                {16, 16, 16, 16},
                {16, 16, 16, 16}};

        AES.keySize = 4;
        AES.roundKeys = new int[4][44];
        AES.stateArray = new int[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                AES.roundKeys[j][i] = initKey[j][i];
                AES.stateArray[i][j] = initState[i][j];
            }
        }
        AES.keyExpansion();
        AES.cipher();
        AES.invCipher();

        Assert.assertArrayEquals(initState, AES.stateArray);
        AES.roundCon = new int[]{0x01, 0, 0, 0};
    }

    @Test
    public void testInvShiftRows() {
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

        AES.stateArray = unShifted;
        AES.shiftRows(true);

        Assert.assertArrayEquals(AES.stateArray, shifted);
    }

    @Test
    public void testGaloisMult() {
        Assert.assertEquals(0x23, AES.galoisMult(7, 13));
        Assert.assertEquals(0x5c, AES.galoisMult(12, 13));
        Assert.assertEquals(0x48, AES.galoisMult(14, 12));
        Assert.assertEquals(0x27, AES.galoisMult(5, 11));
        Assert.assertEquals(0x77, AES.galoisMult(9, 15));
        Assert.assertEquals(0x26, AES.galoisMult(2, 19));
        Assert.assertEquals(0x31, AES.galoisMult(7, 11));
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

