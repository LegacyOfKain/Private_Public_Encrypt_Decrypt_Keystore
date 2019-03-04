// Code referenced by me = https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede

import javax.crypto.Cipher;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
 
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import org.apache.commons.codec.binary.Base64;


public class RsaExample {
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks
        // For listing all the certs
    	//keytool.exe -list -v -keystore keystore.jks
        // For exporting the certificate
    	//keytool -export -alias mykey -file mydomain.crt -keystore keystore.jks
    	
    	FileInputStream ins = new FileInputStream("KeyPair/keystore.jks");
        //InputStream ins = RsaExample.class.getResourceAsStream("KeyPair/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password save in secure location
        KeyStore.PasswordProtection keyPassword =     //Key password save in secure location
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        System.out.println(" Keystore contains alias = "+keyStore.containsAlias("mykey"));
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        System.out.println(cert.getType());
        //System.out.println(cert);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText, PrivateKey privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        return Base64.encodeBase64String(cipherText);
    }

    public static String decrypt(String cipherText, PublicKey publicKey) throws Exception {
        byte[] bytes = Base64.decodeBase64(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKey);

        return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.encodeBase64String(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] signatureBytes = Base64.decodeBase64(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static void main(String args[]) throws Exception {
        //First generate a public/private key pair
        //KeyPair pair = generateKeyPair();
        KeyPair pair = getKeyPairFromKeyStore();

        //Our secret message
        String message = "the answer to life the universe and everything";

        //Encrypt the message
        String cipherText = encrypt(message, pair.getPrivate());

        //Now decrypt it
        String decipheredMessage = decrypt(cipherText, pair.getPublic());

        
        // This is the section where the crt file shared with another user will come to play
        
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        InputStream ins = new FileInputStream("KeyPair/mydomain.crt");
        Certificate certificate = f.generateCertificate(ins);
        PublicKey pk = certificate.getPublicKey();
        
        //Now decrypt it using the public key from exported certificate
        String decipheredMessage2 = decrypt(cipherText, pk);
        
        System.out.println("Original Message: " + message + 
    			"\nEncrypted Message: " + cipherText
    			+ "\nDecrypted Message: " + decipheredMessage 
    			+ "\nDecrypted Message from Exported Cert: " + decipheredMessage2);

        /*
        //Let's sign our message
        String signature = sign("foobar", pair.getPrivate());

        //Let's check the signature
        boolean isCorrect = verify("foobar", signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
        */
    }
}
