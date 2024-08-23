package ma.ensa.crypto.cryptage;

import ma.ensa.crypto.CryptoUtilImpl;
import ma.ensa.crypto.secretKey.SecretKeyManageFile;

import javax.crypto.SecretKey;
import java.util.Arrays;

public class SymetricCryptageAES {

    public static void main(String[] args) throws Exception {
        String message="je ne suis pas pour";
        String secret="meryem_ouyouss_m";

        /*Cipher cipher=Cipher.getInstance("AES");
        SecretKey secretKey=new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] bytes = cipher.doFinal(message.getBytes());
        String encodedEncrytedMessage = Base64.getEncoder().encodeToString(bytes);
        System.out.println(message);
        System.out.println(encodedEncrytedMessage);*/

        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        String s1 = cryptoUtil.crypterWithAES(message, secret);
        System.out.println(s1);

        SecretKey secretKey=cryptoUtil.generateSecretKey();
        System.out.println(secretKey);
        SecretKeyManageFile saveInFile=new SecretKeyManageFile();
        saveInFile.saveSecretKeyToFile(secretKey,"secretKey.txt");

        System.out.println("crypter *****************************");
        String s = cryptoUtil.crypterWithAESSecretKey(message, secretKey);
        System.out.println(s);


    }
}
