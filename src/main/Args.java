/*
 * Author: Spencer Little
 * Date: 08/29/19
 * A class to specify and parse cli arguments for the Main class
 */
package main;

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

    @Parameter(names = { "-v", "-init-vector" }, description = "Path to initialization vector file.", required = true)
    public String initVectorFilePath;

    @Parameter(names = { "-CTR", "--counter-mode" }, description = "Counter (CTR) mode")
    public boolean counterMode = false;

    @Parameter(names = { "-h", "--help" }, description = "Display help message")
    public boolean help = false;

    /*
     * Displays a help message specifying accepted and required cli arguments
     */
    public static void showHelp() {
        String help = "Options: \njava AES \n-f|-filepath <path to file to be encrypted> " +
                "\n-o|-output <filename for output> " +
                "\n-k|-key <path to keyfile or plaintext key> " +
                "\n-v|-init-vector <path to initialization vector file>" +
                "\n-CTR|--counter-mode counter mode" +
                "\n-d|-decrypt specifes decryption mode" +
                "\n-h|--help displays this help message" +
                "\nNote: Default mode is CBC. Initialization vector files must provide exactly 16 bytes.";
        System.out.println(help);
    }
}
