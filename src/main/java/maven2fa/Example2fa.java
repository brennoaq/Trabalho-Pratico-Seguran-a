/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 * Carla Merkle Westphall
 * Adaptado de: https://medium.com/@ihorsokolyk/two-factor-authentication-with-java-and-google-authenticator-9d7ea15ffee6
 * RFCs relevantes:
 *
 * http://tools.ietf.org/html/rfc4226 - HOTP: An HMAC-Based One-Time Password Algorithm
 * http://tools.ietf.org/html/rfc6238 - TOTP: Time-Based One-Time Password Algorithm
 *
 * Para ler: https://levelup.gitconnected.com/how-google-authenticator-hmac-based-one-time-password-and-time-based-one-time-password-work-17c6bdef0deb
 *
 */
package maven2fa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import java.security.SecureRandom;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import de.taimos.totp.TOTP;
import java.io.IOException;
import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;
import com.google.zxing.common.BitMatrix;
import java.io.FileOutputStream;

/**
 *
 * @author Carla Merkle Westphall Adaptado de:
 * https://medium.com/@ihorsokolyk/two-factor-authentication-with-java-and-google-authenticator-9d7ea15ffee6
 *
 */
public class Example2fa {

    public static String convertBase32(byte[] key) {
        Base32 base32 = new Base32();
        return base32.encodeToString(key);
    }

    // https://github.com/taimos/totp/blob/master/src/main/java/de/taimos/totp/TOTP.java
    // TOTP Code permanece válido por 30 segundos
    public static String getTOTPCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }

    public static String getGoogleAuthenticatorBarCode(String secretKey, String account, String issuer) {
        try {
            return "otpauth://totp/"
                    + URLEncoder.encode(issuer + ":" + account, "UTF-8").replace("+", "%20")
                    + "?secret=" + URLEncoder.encode(secretKey, "UTF-8").replace("+", "%20")
                    + "&issuer=" + URLEncoder.encode(issuer, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void createQRCode(String barCodeData, String filePath, int height, int width)
            throws WriterException, IOException {
        BitMatrix matrix = new MultiFormatWriter().encode(barCodeData, BarcodeFormat.QR_CODE,
                width, height);
        try (FileOutputStream out = new FileOutputStream(filePath)) {
            MatrixToImageWriter.writeToStream(matrix, "png", out);
        }

    }
}
