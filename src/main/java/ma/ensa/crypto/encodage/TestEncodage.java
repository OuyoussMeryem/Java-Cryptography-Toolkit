package ma.ensa.crypto.encodage;

import ma.ensa.crypto.CryptoUtilImpl;
import org.apache.commons.codec.binary.Hex;

public class TestEncodage {
    public static void main(String[] args) {

        /*String message="This is me>>>>>";
        byte[] bytes = message.getBytes();
        System.out.println(message);
        System.out.println(Arrays.toString(bytes));
        String s = Base64.getEncoder().encodeToString(bytes);
        System.out.println(s);
        byte[] decoded = Base64.getDecoder().decode(s);
        System.out.println(new String(decoded));
        System.out.println(message);
        String s1 = Base64.getUrlEncoder().encodeToString(message.getBytes());
        System.out.println(s1);
        byte[] decode = Base64.getUrlDecoder().decode(s1);
        System.out.println(new String(decode));*/

        CryptoUtilImpl cryptoUtil=new CryptoUtilImpl();
        //VGhpcyBpcyBtZT4+Pj4+
        String message="This is me>>>>>";
        String encodeToBase64 = cryptoUtil.toBase64(message);
        System.out.println(encodeToBase64);
        String resultBase64=cryptoUtil.fromBase64(encodeToBase64);
        System.out.println(resultBase64);


        //VGhpcyBpcyBtZT4-Pj4-
        String message2="This is me>>>>>";
        String encodeToBase64URL = cryptoUtil.toBase64URL(message2);
        System.out.println(encodeToBase64URL);
        String resultBase64Url=cryptoUtil.fromBase64URL(encodeToBase64URL);
        System.out.println(resultBase64Url);
        //54686973206973206D653E3E3E3E3E
        String s = cryptoUtil.ConverteToHexaDecimal(message2);
        System.out.println(s);
        System.out.println("fromHexaDecimal: "+cryptoUtil.fromHexaDecimal(s));
        System.out.println("Hex.encodeHex: "+Hex.encodeHexString(message2.getBytes()));
        System.out.println("ConverteToHexaDecimalApachCodec: "+cryptoUtil.ConverteToHexaDecimalApachCodec(message2));
        System.out.println("toHexNative: "+cryptoUtil.toHexNative(message));
    }
}
