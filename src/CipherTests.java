/**
 * Author: Spencer Little
 * Date: 08/29/2019
 * A set of unit tests for the various functions of the AES cipher
 * Note: Must be run individually, testing round constant interferes with key schedule
 */

import org.junit.Test;
import org.junit.Assert;

import java.io.FileInputStream;
import java.io.IOException;

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

        Assert.assertArrayEquals(resultWord, AES.mixColumnWord(initWord));
        Assert.assertArrayEquals(initWord, AES.invMixColumnWord(resultWord));
        Assert.assertArrayEquals(resultWordTwo, AES.mixColumnWord(initWordTwo));
        Assert.assertArrayEquals(initWordTwo, AES.invMixColumnWord(resultWordTwo));
        Assert.assertArrayEquals(resultWordThree, AES.mixColumnWord(initWordThree));
        Assert.assertArrayEquals(initWordThree, AES.invMixColumnWord(resultWordThree));
        Assert.assertArrayEquals(resultWordFour, AES.mixColumnWord(initWordFour));
        Assert.assertArrayEquals(initWordFour, AES.invMixColumnWord(resultWordFour));
        Assert.assertArrayEquals(resultWordFive, AES.mixColumnWord(initWordFive));
        Assert.assertArrayEquals(initWordFive, AES.invMixColumnWord(resultWordFive));
        Assert.assertArrayEquals(resultWordSix, AES.mixColumnWord(initWordSix));
        Assert.assertArrayEquals(initWordSix, AES.invMixColumnWord(resultWordSix));
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

        AES.roundCon = new int[]{0x01, 0, 0, 0}; // reset round constant to avoid interference with other tests
    }

    @Test
    public void testRotWord() {
        int[] initWord = {1, 2, 3, 4};
        int[] resultWord = {2, 3, 4, 1};

        Assert.assertArrayEquals(resultWord, AES.rotWord(initWord));
    }

    @Test
    public void testKeyExpansion() {
        //TODO: Add tests for other key sizes
        AES.keySize = 4;
        int[][] initKey = { // Values lifted from example provided in AES Specification Appendix A pg. 27
                {0x2b, 0x7e, 0x15, 0x16},
                {0x28, 0xae, 0xd2, 0xa6},
                {0xab, 0xf7, 0x15, 0x88},
                {0x09, 0xcf, 0x4f, 0x3c}};
        int[] roundFour = {0xa0, 0xfa, 0xfe, 0x17};
        int[] roundTen = {0x59, 0x35, 0x80, 0x7a};
        int[] roundTwentyThree = {0x11, 0xf9, 0x15, 0xbc};
        int[] roundFourtyThree = {0xb6, 0x63, 0x0c, 0xa6};
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

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.print(AES.stateArray[i][j] + ",");
            }
            System.out.println();
        }

        Assert.assertArrayEquals(initState, AES.stateArray);
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

        int toWrite = 16 - stateArray[3][3];
        i = 0; j = 0;
        while (toWrite > 0) {
            stateArray[j][i] = 101;
            toWrite--;
            j++;
            if (j == 4) {i++; j = 0;}
        }

        for (int z =0; z < 4; z++) {
            for (int a = 0; a < 4; a++) {
                System.out.print(stateArray[z][a] + ",");
            }
            System.out.println();
        }
    }


}

