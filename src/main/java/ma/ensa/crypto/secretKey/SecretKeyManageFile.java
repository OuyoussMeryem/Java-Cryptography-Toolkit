package ma.ensa.crypto.secretKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Base64;

public class SecretKeyManageFile {

    public void saveSecretKeyToFile(SecretKey secretKey, String fileName) {
        try {
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            File file = new File(fileName);
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(encodedKey);
            }
            System.out.println("Clé secrète sauvegardée dans le fichier : " + file.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public SecretKey loadSecretKeyFromFile(String fileName) {
        try {

            File file = new File(fileName);
            String encodedKey = new String(Files.readAllBytes(file.toPath()));
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            return secretKey;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
