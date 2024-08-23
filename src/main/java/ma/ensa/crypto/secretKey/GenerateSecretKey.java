package ma.ensa.crypto.secretKey;

import ma.ensa.crypto.CryptoUtilImpl;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Base64;

public class GenerateSecretKey {

    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        SecretKey secretKey = cryptoUtil.generateSecretKey();
        //16 elements ---->128 bites
        byte[] encodedSecret = secretKey.getEncoded();
        System.out.println(Arrays.toString(encodedSecret));
        System.out.println(new String(encodedSecret));
        System.out.println(Base64.getEncoder().encodeToString(encodedSecret));
    }
}
