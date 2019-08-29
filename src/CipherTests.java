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
                {37,45,10,242},
                {80,49,37,229},
                {68,46,196,235},
                {70,51,229,167}};

        int[][] shifted =  {
                {37,45,10,242},
                {49,37,229,80}, // shifted left by one byte (w/ wrap around)
                {196,235,68,46}, // shifted left by two bytes
                {167,70,51,229}}; // shifted left by three bytes

        AES.stateArray = unShifted;
        AES.shiftRows();

        Assert.assertArrayEquals(AES.stateArray, shifted);
    }

}
