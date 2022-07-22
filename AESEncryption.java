import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryption {

    public static final String FOLDER_PATH="D:\\Manoo\\";
    private static final String FILE ="aws";
    private static final String EXT=".pdf";

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int KEY_SIZE =128;


    public static void main(String[] args)throws Exception{

        // TODO Auto-generated method stub
        KeyGenerator kgen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        kgen.init(KEY_SIZE);
        SecretKey skey = kgen.generateKey();
        byte[] secretkey = skey.getEncoded();
        SecretKeySpec skeySpec = new SecretKeySpec(secretkey, ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

        //load file encrypt
        byte[] largeFileBytes = Files.readAllBytes(Paths.get(FOLDER_PATH+FILE+EXT));


        //Encrypt the file
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] largeFileEncBytes = cipher.doFinal(largeFileBytes);

        //save Encrpyted file
        Files.write(Paths.get(FOLDER_PATH+FILE+"-encrypted" +EXT),largeFileEncBytes);

        //Load Encrypted file
        byte[] largeFileEncBytesTocheck =Files.readAllBytes(Paths.get(FOLDER_PATH+FILE+"-encrypted"+EXT));

        //Decrypt file
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] largeFileBytesTocheck = cipher.doFinal(largeFileEncBytesTocheck);

        //save decrypted file
        Files.write(Paths.get(FOLDER_PATH+FILE+"-decrypted"+EXT), largeFileEncBytesTocheck);

        //compare the results
        if(Arrays.equals(largeFileBytes,largeFileBytesTocheck))
        {

            System.out.println("Ok");
        }
        else
        {

            System.out.println("ko");
        }

    }

}
