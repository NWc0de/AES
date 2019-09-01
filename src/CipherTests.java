/**
 * Author: Spencer Little
 * Date: 08/29/2019
 * A set of unit tests for the various functions of the AES cipher
 */

import org.junit.Test;
import org.junit.Assert;

public class CipherTests {

    /*
     * Tests the row shifting operations
     * ref. NIST AES specification figure 8. sec 5.1.2 pg. 17
     */
    @Test
    public void testShiftRows() {
        int[][] unShifted =  {
                {37,45,10,242},
                {80,49,37,229},
                {68,46,196,235},
                {70,51,229,167}};

        int[][] shifted =  {
                {37,45,10,242},
                {49,37,229,80}, // shifted left by one byte
                {196,235,68,46}, // shifted left by two bytes
                {167,70,51,229}}; // shifted left by three bytes

        AES.stateArray = unShifted;
        AES.shiftRows();

        Assert.assertArrayEquals(AES.stateArray, shifted);
    }

    /*
     * Tests the column mixing operation
     */
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
        Assert.assertArrayEquals(resultWordTwo, AES.mixColumnWord(initWordTwo));
        Assert.assertArrayEquals(resultWordThree, AES.mixColumnWord(initWordThree));
        Assert.assertArrayEquals(resultWordFour, AES.mixColumnWord(initWordFour));
        Assert.assertArrayEquals(resultWordFive, AES.mixColumnWord(initWordFive));
        Assert.assertArrayEquals(resultWordSix, AES.mixColumnWord(initWordSix));
    }

    /*
     * Tests the rotWord method
     */
    @Test
    public void testRotWord() {
        int[] initWord = {1, 2, 3, 4};
        int[] resultWord = {2, 3, 4, 1};

        Assert.assertArrayEquals(resultWord, AES.rotWord(initWord));
    }

    /*
     * Tests the round constant generator
     */
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
    }

}

