package ma.ensa.crypto.cryptage;

import ma.ensa.crypto.CryptoUtilImpl;
import ma.ensa.crypto.secretKey.SecretKeyManageFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class SymetricDecryptageAES {
    public static void main(String[] args) throws Exception{
         String messageEncoderCrypter="Mg9Bt4nzXi45g7wcJwJsrTvJlZL4lTf05gLDHX0YTyA=";
         String secret="meryem_ouyouss_m";

         /*byte[] decodedEncryptedMessage = Base64.getDecoder().decode(messageEncoderCrypter.getBytes());
         System.out.println(Arrays.toString(decodedEncryptedMessage));
         SecretKey secretKey=new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
         Cipher cipher=Cipher.getInstance("AES");
         cipher.init(Cipher.DECRYPT_MODE,secretKey);
         byte[] bytes = cipher.doFinal(decodedEncryptedMessage);
         String messageDecodedDecrypted=new String(bytes);
         System.out.println(messageDecodedDecrypted);*/

         CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();

         String message="w8tOauPqYXV4A58pbh66aFHhiZjO9ARdxW1kfdKCdDU=";
         String s1 = cryptoUtil.decrypterWithAES(message, secret);
         System.out.println(s1);

         SecretKeyManageFile secretKeyManageFile=new SecretKeyManageFile();
         SecretKey secretKey = secretKeyManageFile.loadSecretKeyFromFile("secretKey.txt");
         System.out.println("decrypter *****************************");
         String s = cryptoUtil.decrypterWithAESSecretKey(messageEncoderCrypter, secretKey);
         System.out.println(s);
    }
}
