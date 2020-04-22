package udptotcp;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;

public class FileReader {
    private BufferedInputStream fileIn;
    private long fileLength;
    private int MSS;
    public FileReader(String filename, int MSS) throws IOException {
        this.fileIn = new BufferedInputStream(new FileInputStream(filename), MSS);
        this.fileLength = fileIn.available();
        this.MSS = MSS;
    }

    public byte[] readFile(int position)throws IOException{
        if(position > this.fileLength){
            return null;
        }
        fileIn.skip(position);
        if(this.fileLength-position > this.MSS) {
            byte[] array = new byte[this.MSS];
            fileIn.read(array);
            return array;
        }else{
            byte[] array = new byte[(int)this.fileLength-position];
            fileIn.read(array);
            return array;
        }
    }

    public void close() throws IOException {
        fileIn.close();
    }

}

