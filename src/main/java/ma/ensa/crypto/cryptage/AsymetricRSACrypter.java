package ma.ensa.crypto.cryptage;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymetricRSACrypter {
    public static void main(String[] args) throws Exception {

        /*KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey=keyPair.getPrivate();
        PublicKey publicKey=keyPair.getPublic();
        System.out.println("Private Key **********************");
        byte[] encodedPrivateKey = privateKey.getEncoded();
        System.out.println(new String(encodedPrivateKey));
        System.out.println(Arrays.toString(encodedPrivateKey));
        String s = Base64.getEncoder().encodeToString(encodedPrivateKey);
        System.out.println(s);
        System.out.println("Public Key **********************");
        byte[] encodedPublicKey = publicKey.getEncoded();
        System.out.println(new String(encodedPublicKey));
        System.out.println(Arrays.toString(encodedPublicKey));
        String s1 = Base64.getEncoder().encodeToString(encodedPublicKey);
        System.out.println(s1);*/

        /*
        private key *************************
        MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvQgxgvhGI66DCZbRSlcMptMPqKMWxrZa0qBERRwsjJMfvj6RVqd54+O/XjjTaoPwafYGfRWIuh0TSHIx16z0ZQIDAQABAkAECYgPk7oUkM/kPtZ2EuYTYAzRdx48gz0gV3ztyIkpCjS+hQlDI6rGt1w65BtMySxU3XqM6qY1PpB/pX5KYNo3AiEAysQwQ6SDioMveFKk0znV9iBzKRzF95C03DXiJMlfGo8CIQDuqO04igtLzF5c1ksw/P99zQezErnqsM9vF3c+VVVLywIhAMptEE4HaHcYvoRd5UUmoS9ld/KcUhr0MUsC1DCrhLGLAiEAsb1NLlZgo0rI3AscZJeHD4Gqwkqn+4lCc1HelKWoqJECIGrNzbaHNhaAnUEgKWzEBqqTParv3caAsiYWA24NmtwY
        public key *************************
        MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL0IMYL4RiOugwmW0UpXDKbTD6ijFsa2WtKgREUcLIyTH74+kVaneePjv14402qD8Gn2Bn0ViLodE0hyMdes9GUCAwEAAQ==
        */

        String publicKeyEncoderBase64="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL0IMYL4RiOugwmW0UpXDKbTD6ijFsa2WtKgREUcLIyTH74+kVaneePjv14402qD8Gn2Bn0ViLodE0hyMdes9GUCAwEAAQ==";
        String data="je veux tester le RSA algorithm";
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodePublicKey = Base64.getDecoder().decode(publicKeyEncoderBase64);
        PublicKey publicKey=keyFactory.generatePublic(new X509EncodedKeySpec(decodePublicKey));

        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = cipher.doFinal(data.getBytes());
        String s = Base64.getEncoder().encodeToString(bytes);
        System.out.println(s);

    }

}
