package ma.ensa.crypto.cryptage;

import ma.ensa.crypto.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSATestCrypterDecrypter {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        KeyPair keyPair = cryptoUtil.generateKeypair();
        PrivateKey privateKey=keyPair.getPrivate();
        PublicKey publicKey=keyPair.getPublic();

        String dataMessage="Hi, How are you";
        String s = cryptoUtil.crypterWithRSA(dataMessage, publicKey);
        System.out.println("-------crypted Message---------------");
        System.out.println(s);
        System.out.println("-------decrypted Message---------------");
        String s1 = cryptoUtil.decrypterWithRSA(s, privateKey);
        System.out.println(s1);


    }
}
