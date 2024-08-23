package ma.ensa.crypto;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class CryptoUtilImpl {

    public String toBase64(String message){
        byte[] bytes = message.getBytes();
        String messageEncodeToString = Base64.getEncoder().encodeToString(bytes);
        return messageEncodeToString;
    }

    public String fromBase64(String messageEncodeToString){
        byte[] decodedMessage = Base64.getDecoder().decode(messageEncodeToString);
        String message=new String(decodedMessage);
        return message;
    }

    public String toBase64URL(String message){
        byte[] bytes = message.getBytes();
        String messageEncodeToString = Base64.getUrlEncoder().encodeToString(bytes);
        return messageEncodeToString;
    }

    public String fromBase64URL(String messageEncodeToString){
        byte[] decodedMessage = Base64.getUrlDecoder().decode(messageEncodeToString);
        String message=new String(decodedMessage);
        return message;
    }

    public String ConverteToHexaDecimal(String message){
        byte[] bytes = message.getBytes();
        String s = DatatypeConverter.printHexBinary(bytes);
        return s;
    }
    public String fromHexaDecimal(String message){
        byte[] bytes = DatatypeConverter.parseHexBinary(message);
        String s=new String(bytes);
        return s;
    }

    public String ConverteToHexaDecimalApachCodec(String message){
        byte[] bytes = message.getBytes();
        String s= Hex.encodeHexString(bytes);
        return s;
    }

    public String toHexNative(String message){
        byte[] bytes = message.getBytes();
        Formatter formatter=new Formatter();
        for(byte b:bytes){
            formatter.format("%02x",b);
        }
        return formatter.toString();
    }

   public SecretKey generateSecretKey() throws Exception{
       KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
       keyGenerator.init(128);
       return keyGenerator.generateKey();
   }

    public String crypterWithAES(String message, String secret) throws Exception {
        byte[] bytes = message.getBytes();
        SecretKey secretKey=new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptedMessage= cipher.doFinal(bytes);
        String encodedEncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        return  encodedEncryptedMessage;
    }

    public String decrypterWithAES(String messageCrypterEncoder,String secret) throws Exception {
        SecretKey secretKey=new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
        byte[] messageCrypted = Base64.getDecoder().decode(messageCrypterEncoder.getBytes());
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] messageDecrypted = cipher.doFinal(messageCrypted);

        return new String(messageDecrypted);
    }

    public String crypterWithAESSecretKey(String message, SecretKey secretKey) throws Exception {
        byte[] bytes = message.getBytes();
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptedMessage= cipher.doFinal(bytes);
        String encodedEncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        return  encodedEncryptedMessage;
    }

    public String decrypterWithAESSecretKey(String messageCrypterEncoder,SecretKey secretKey) throws Exception {
        byte[] messageCrypted = Base64.getDecoder().decode(messageCrypterEncoder.getBytes());
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] messageDecrypted = cipher.doFinal(messageCrypted);

        return new String(messageDecrypted);
    }

    public KeyPair generateKeypair() throws Exception {
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);

        return  keyPairGenerator.generateKeyPair();
    }

    public PublicKey publicKeyFromBase64(String publicKeyInput) throws Exception {
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodePublicKey = Base64.getDecoder().decode(publicKeyInput);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodePublicKey));
        return publicKey;
    }

    public PrivateKey privateKeyFromBase64(String privateKeyInput) throws Exception {
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodePrivateKey = Base64.getDecoder().decode(privateKeyInput);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodePrivateKey));
        return privateKey;
    }

    public String crypterWithRSA(String message,PublicKey publicKey) throws Exception {
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = cipher.doFinal(message.getBytes());
        String s = Base64.getEncoder().encodeToString(bytes);
        return s;
    }

    public String decrypterWithRSA(String messageCrypterEncoder,PrivateKey privateKey)throws Exception{
        byte[] decodeMessageCrypter = Base64.getDecoder().decode(messageCrypterEncoder);
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] bytes = cipher.doFinal(decodeMessageCrypter);
        return new String(bytes);
    }


    public PublicKey publicKeyFromCertificate(String fileName)throws Exception{
        FileInputStream fileInputStream=new FileInputStream(fileName);
        CertificateFactory certificateFactory=CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        System.out.println(certificate);
        return certificate.getPublicKey();
    }

    public PrivateKey privateKeyFromKeystoreJKS(String fileName,String keystorPassword,String alias)throws Exception{
        FileInputStream fileInputStream=new FileInputStream(fileName);
        KeyStore keyStore=KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream,keystorPassword.toCharArray());
        Key key = keyStore.getKey(alias, keystorPassword.toCharArray());
        PrivateKey privateKey= (PrivateKey) key;
        return privateKey;

    }

    public String generateSignWithHmac(String messageDoc,String secret)throws Exception{
        SecretKeySpec secretKeySpec=new SecretKeySpec(secret.getBytes(),"HmacSHA256");
        Mac mac=Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] signature = mac.doFinal(messageDoc.getBytes());
        return Base64.getEncoder().encodeToString(signature);
    }

    public boolean verifySignatureHmac(String documentSign,String secret)throws Exception{
        //separer le message de la signature
        String[] splitedDocument=documentSign.split("---");
        String docoment=splitedDocument[0];
        String signature=splitedDocument[1];
        System.out.println("partie 1 "+docoment);
        System.out.println("partie 2 "+signature);
        //hasher le message
        SecretKeySpec secretKeySpec=new SecretKeySpec(secret.getBytes(),"HmacSHA256");
        Mac mac=Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        byte[] bytes = mac.doFinal(docoment.getBytes());
        String signatureForTest=Base64.getEncoder().encodeToString(bytes);

        return (signatureForTest.equals(signature));

    }

    public String generateSignWithRSA(String message,PrivateKey privateKey)throws Exception{
        Signature signature=Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey,new SecureRandom());
        signature.update(message.getBytes());
        byte[] signatureGenerated = signature.sign();
        String s = Base64.getEncoder().encodeToString(signatureGenerated);
        return s;
    }

    public boolean verifySignatureRSA(String documentSign,PublicKey publicKey)throws Exception{
        Signature signature=Signature.getInstance("SHA256withRSA");
        String[] splitedDocument=documentSign.split("---");
        String document=splitedDocument[0];
        String sign=splitedDocument[1];
        byte[] decode = Base64.getDecoder().decode(sign);
        signature.initVerify(publicKey);
        signature.update(document.getBytes());
        boolean verify = signature.verify(decode);
        return verify;
    }
}





























