package ma.ensa.crypto.cryptage;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymetricRSADecrypter {
    public static void main(String[] args) throws Exception{

        String privateKeyEncoderBase64="MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAvQgxgvhGI66DCZbRSlcMptMPqKMWxrZa0qBERRwsjJMfvj6RVqd54+O/XjjTaoPwafYGfRWIuh0TSHIx16z0ZQIDAQABAkAECYgPk7oUkM/kPtZ2EuYTYAzRdx48gz0gV3ztyIkpCjS+hQlDI6rGt1w65BtMySxU3XqM6qY1PpB/pX5KYNo3AiEAysQwQ6SDioMveFKk0znV9iBzKRzF95C03DXiJMlfGo8CIQDuqO04igtLzF5c1ksw/P99zQezErnqsM9vF3c+VVVLywIhAMptEE4HaHcYvoRd5UUmoS9ld/KcUhr0MUsC1DCrhLGLAiEAsb1NLlZgo0rI3AscZJeHD4Gqwkqn+4lCc1HelKWoqJECIGrNzbaHNhaAnUEgKWzEBqqTParv3caAsiYWA24NmtwY";
        String dataEncrypterEncoded="kTgzN0/m8Xmu+GZPYSsBVDYZCMYe970oHpnEDsEoH5Wp1sVgP6N4swErGTrdq7Y9Tzk6NJtRet67SF2+ZE1XeQ==";
        byte[] dataEncrypted = Base64.getDecoder().decode(dataEncrypterEncoded);
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        byte[] decodePrivateKey = Base64.getDecoder().decode(privateKeyEncoderBase64);
        PrivateKey privateKey=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodePrivateKey));

        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] bytes = cipher.doFinal(dataEncrypted);
        System.out.println(new String(bytes));

    }

}
