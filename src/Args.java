/**
 * Author: Spencer Little
 * Date: 08/29/19
 * A class to specify and parse cli arguments for the Main class
 */

import com.beust.jcommander.Parameter;

public class Args {
    @Parameter(names = { "-f", "-filepath" }, description = "Path to the file to be encrypted.")
    public String filePath;

    @Parameter(names = { "-o", "-output" }, description = "File name for the output.")
    public String output;

    @Parameter(names = { "-k", "-key" }, description = "Path to key file, or key in plaintext.")
    public String keyFilePath;

    /*
     * Displays a help message specifying accepted and required cli arguments
     */
    public static void showHelp() {
        String help = "Usage: \njava AES -f|-filepath <path to file to be encrypted> " +
                "-o|-output <filename for output> " +
                "-k|key <path to keyfile or plaintext key> " +
                "-e|encrypt or -d|decrypt";
        System.out.println(help);
    }
}
