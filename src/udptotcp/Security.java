package udptotcp;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
public class Security {
    public KeyPair genKeyPair(int keyLength) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyLength);
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] encryptByPublicKey(byte[] content, PublicKey publicKey) throws Exception{
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int inputlen = content.length;
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        for(int i = 0; inputlen - offSet > 0; offSet = i * 117) {
            byte[] cache;
            if(inputlen - offSet > 117) {
                cache = cipher.doFinal(content, offSet, 117);
            } else {
                cache = cipher.doFinal(content, offSet, inputlen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] encrypteData = out.toByteArray();
        out.close();
        return encrypteData;
    }

    public byte[] encryptByPrivateKey(byte[] content, PrivateKey privateKey) throws Exception{
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int inputlen = content.length;
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        for(int i = 0; inputlen - offSet > 0; offSet = i * 117) {
            byte[] cache;
            if(inputlen - offSet > 117) {
                cache = cipher.doFinal(content, offSet, 117);
            } else {
                cache = cipher.doFinal(content, offSet, inputlen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] encrypteData = out.toByteArray();
        out.close();
        return encrypteData;
    }

    public byte[] decryptByPrivateKey(byte[] content, PrivateKey privateKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int inputlen = content.length;
        for(int i = 0; inputlen - offSet > 0; offSet = i * 128) {
            byte[] cache;
            if(inputlen - offSet > 128) {
                cache = cipher.doFinal(content, offSet, 128);
            } else {
                cache = cipher.doFinal(content, offSet, inputlen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    public byte[] decryptByPublicKey(byte[] content, PublicKey publicKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int inputlen = content.length;
        for(int i = 0; inputlen - offSet > 0; offSet = i * 128) {
            byte[] cache;
            if(inputlen - offSet > 128) {
                cache = cipher.doFinal(content, offSet, 128);
            } else {
                cache = cipher.doFinal(content, offSet, inputlen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

}
