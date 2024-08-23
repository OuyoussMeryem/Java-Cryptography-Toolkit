package ma.ensa.crypto.cryptage;

import ma.ensa.crypto.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class GenaratePairKey {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        KeyPair keyPair=cryptoUtil.generateKeypair();
        PrivateKey privateKey=keyPair.getPrivate();
        PublicKey publicKey=keyPair.getPublic();
        System.out.println("private key *************************");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("public key *************************");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }
}
