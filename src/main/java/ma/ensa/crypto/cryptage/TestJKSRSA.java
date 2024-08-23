package ma.ensa.crypto.cryptage;

import ma.ensa.crypto.CryptoUtilImpl;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestJKSRSA {
    public static void main(String[] args) throws Exception{
        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        PublicKey publicKey = cryptoUtil.publicKeyFromCertificate("publicKey.cert");
        System.out.println(cryptoUtil.toBase64(new String(publicKey.getEncoded())));
        PrivateKey privateKey = cryptoUtil.privateKeyFromKeystoreJKS("meryem.jks", "123456", "meryem");
        System.out.println(cryptoUtil.toBase64(new String(privateKey.getEncoded())));

        String message="Full stack developper";
        System.out.println("----crypter*****");
        String s = cryptoUtil.crypterWithRSA(message, publicKey);
        System.out.println(s);
        System.out.println("----decrypter*******");
        String s1 = cryptoUtil.decrypterWithRSA(s, privateKey);
        System.out.println(s1);

    }
}
