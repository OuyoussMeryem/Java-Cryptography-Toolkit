package ma.ensa.crypto.cryptage;

import ma.ensa.crypto.CryptoUtilImpl;

import java.util.Arrays;


public class TestSignatureHmac {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        String secret="meryem";
        String message="this is me message !!";

        String s = cryptoUtil.generateSignWithHmac(message, secret);
        String messageWithSignature=message+"---"+s;
        System.out.println(messageWithSignature);


        String messageRecu="this is me message !!---vJKarXLx+afg4lJMGMc/y/RqV0hxrw7cR8ix8TouLjY=";
        boolean b = cryptoUtil.verifySignatureHmac(messageRecu, secret);
        System.out.println(b?"Signature OK":"Signature Not OK");
    }
}
