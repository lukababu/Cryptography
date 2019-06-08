import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileEncryption {
    private FileInputStream in_file;
    private FileOutputStream out_file;
    private String inputFile;
    private String outputFile;
    private String seed;
    private boolean pass;

    private FileEncryption() {
        setPass(false);
        setIn_file(null);
        setOut_file(null);
    }

    protected FileEncryption(String inputFile, String outputFile, String seed) throws IOException {
        this();
        setInputFile(inputFile);
        setOutputFile(outputFile);
        setSeed(seed);
    }

    /**
     * Getter Methods
     */
    protected FileInputStream getIn_file() {
        return in_file;
    }

    protected FileOutputStream getOut_file() {
        return out_file;
    }

    protected String getInputFile() {
        return inputFile;
    }

    protected String getOutputFile() {
        return outputFile;
    }

    protected String getSeed() {
        return seed;
    }

    public boolean isPass() {
        return pass;
    }

    /**
     * Setter Methods
     */
    protected void setIn_file(FileInputStream in_file) {
        this.in_file = in_file;
    }

    protected void setOut_file(FileOutputStream out_file) {
        this.out_file = out_file;
    }
    protected void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    protected void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    protected void setSeed(String seed) {
        this.seed = seed;
    }

    protected void setPass(boolean pass) {
        this.pass = pass;
    }
}
