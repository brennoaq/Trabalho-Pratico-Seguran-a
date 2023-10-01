package maven2fa;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CypherSecurity {

    public static byte[] encryptMessage(String message, String phone, String key, byte[] salt) throws Exception {
        // Gerar um IV aleatório
        byte[] iv = deriveKeyOrIV(phone, salt, true);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] encryptedText = cipher.doFinal(message.getBytes());

        // Concatenar IV e texto cifrado para armazenamento
        byte[] encryptedMessage = new byte[iv.length + encryptedText.length];
        System.arraycopy(iv, 0, encryptedMessage, 0, iv.length);
        System.arraycopy(encryptedText, 0, encryptedMessage, iv.length, encryptedText.length);

        return encryptedMessage;
    }

    public static String decryptMessage(byte[] encryptedMessageWithIv, String key) throws Exception {
        // Extrair IV e texto cifrado
        byte[] iv = new byte[16];
        System.arraycopy(encryptedMessageWithIv, 0, iv, 0, iv.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        byte[] encryptedText = new byte[encryptedMessageWithIv.length - iv.length];
        System.arraycopy(encryptedMessageWithIv, iv.length, encryptedText, 0, encryptedText.length);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] decryptedMessage = cipher.doFinal(encryptedText);

        return new String(decryptedMessage);
    }

    public static byte[] deriveKeyOrIV(String phone, byte[] salt, boolean isIV) throws Exception {
        int keyLength = isIV ? 128 : 160;
        PBEKeySpec spec = new PBEKeySpec(phone.toCharArray(), salt, 65536, keyLength); // byte[16 : 20]
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded();
    }

}
