/**
 * Author: Spencer Little
 * Date: 08/29/19
 * A class to specify and parse cli arguments for the Main class
 */
package cipher;

import com.beust.jcommander.Parameter;

public class Args {
    @Parameter(names = { "-f", "-filepath" }, description = "Path to the file to be encrypted.", required = true)
    public String filePath;

    @Parameter(names = { "-o", "-output" }, description = "File name for the output.", required = true)
    public String output;

    @Parameter(names = { "-k", "-key" }, description = "Path to key file, or key in plaintext.", required = true)
    public String keyFilePath;

    @Parameter(names = { "-d", "-decrypt" }, description = "Decryption mode.")
    public boolean decrypt = false;

    /*
     * Displays a help message specifying accepted and required cli arguments
     */
    public static void showHelp() {
        String help = "Usage: \njava Cipher.AES -f|-filepath <path to file to be encrypted> " +
                "-o|-output <filename for output> " +
                "-k|key <path to keyfile or plaintext key> " +
                "-d|decrypt";
        System.out.println(help);
    }
}
