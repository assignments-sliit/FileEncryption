import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAEncryption {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        // Generated with:
        // keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg
        // RSA -keystore keystore.jks

        InputStream ins = RSAEncryption.class.getResourceAsStream("/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray()); // Keystore password
        KeyStore.PasswordProtection keyPassword = // Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static final String FOLDER_PATH="D:\\manoo\\";
    private static final String FILE ="aws";
    private static final String EXT=".pdf";

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int KEY_SIZE =128;

    public static void main(String... argv) throws Exception {
        // First generate a public/private key pair
        KeyPair pair = generateKeyPair();
        // KeyPair pair = getKeyPairFromKeyStore();

        // Our secret message
        String message = "We learn RSA algorithm"; //ivaruku bathila than
        //AES start

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

        String keyToString = Base64.getEncoder().encodeToString(skeySpec.getEncoded());

        //AES End

        System.out.println(keyToString);

        // Encrypt the message (RSA)
        String cipherText = encrypt(keyToString, pair.getPublic());

        System.out.println("RSA use panni cipher text ah maarina AES key ah par: "+cipherText);

        // Now decrypt it
        String decipheredMessage = decrypt(cipherText, pair.getPrivate());

        System.out.println(decipheredMessage);

        //again AES

        //Load Encrypted file
        byte[] largeFileEncBytesTocheck =Files.readAllBytes(Paths.get(FOLDER_PATH+FILE+"-encrypted"+EXT));

        if(decipheredMessage.equals(keyToString)){
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
            System.out.println("Ela ela encrypted");
        }else{
            System.out.println(":(");
        }


        //AES again End

//        // Let's sign our message
//        String signature = sign("foobar", pair.getPrivate());
//
//        // Let's check the signature
//        boolean isCorrect = verify("foobar", signature, pair.getPublic());
//        System.out.println("Signature correct: " + isCorrect);
    }
}