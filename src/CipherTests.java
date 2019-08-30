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

}
