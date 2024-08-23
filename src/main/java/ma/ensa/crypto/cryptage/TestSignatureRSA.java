package ma.ensa.crypto.cryptage;

import ma.ensa.crypto.CryptoUtilImpl;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestSignatureRSA {

    public static void main(String[] args) throws Exception{
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        String message="this is a new message";
        PrivateKey privateKey=cryptoUtil.privateKeyFromKeystoreJKS("meryem.jks","123456","meryem");

        String s = cryptoUtil.generateSignWithRSA(message, privateKey);
        String messageWithSign=message+"---"+s;
        System.out.println(messageWithSign);

        System.out.println("===============================");
        String messageRecu="this is a new message---qYvfgfuxAVWX3nyhetB3tzCv1Fh8rzMuOrFPlw6bNe/gh60xCauijYCmVzSsfFXA3iIYRdOD/TlRHjLijb97k1FB4SUHKVhxzn1F44M+RaEXWRRzfXt1INmZAubbYGfnHG5kni4tAUlnCwY0kI98ReEEaW4AiwvGqOt8edxY+ubexh78nl5p/6aXQ/+Y1HsaAuc0Iv8CD4OxXMi0hD8esEU215Vbo9x03gZH7E6Kc7su8RBOrNFvlyEVZ/xbarKiToV9YEn3baRo7z3I44m0o3YDKh9NLPFF6Oly507sGRW99V9CPKfduVYASOvhPNhJEJfbiFpEsGCxNLX/SfYfLg==";
        PublicKey publicKey=cryptoUtil.publicKeyFromCertificate("publicKey.cert");
        boolean b = cryptoUtil.verifySignatureRSA(messageRecu, publicKey);
        System.out.println(b?"Signature with RSA OK":"Signature with RSA Not OK");

    }
}
