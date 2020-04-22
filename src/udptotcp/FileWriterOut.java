package udptotcp;

import java.io.BufferedWriter;
import java.io.File;

public class FileWriterOut {
    public BufferedWriter senderOpenWritingFile() throws Exception{
        File writefile = new File("sender.txt");
        if(!writefile.exists()) {
            writefile.createNewFile();
        }
        BufferedWriter out = new BufferedWriter(new java.io.FileWriter(writefile));
        return out;
    }

    public BufferedWriter receiverOpenWritingFile() throws Exception{
        File writefile = new File("receiver.txt");
        if(!writefile.exists()) {
            writefile.createNewFile();
        }
        BufferedWriter out = new BufferedWriter(new java.io.FileWriter(writefile));
        return out;
    }
}
