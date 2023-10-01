package maven2fa;

import java.security.SecureRandom;
import org.bouncycastle.crypto.fips.Scrypt;
import org.bouncycastle.util.Strings;
import org.bouncycastle.crypto.KDFCalculator;

public class SCRYPT {
    // Gerando um salt aleatorio
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    // Adaptado de https://downloads.bouncycastle.org/fips-java/BC-FJA-UserGuide-1.0.2.pdf
    public static byte[] useScryptKDF(char[] password, byte [] salt, int costParameter, int blocksize, int parallelizationParam ) {
        KDFCalculator<Scrypt.Parameters> calculator
                = new Scrypt.KDFFactory()
                .createKDFCalculator(
                        Scrypt.ALGORITHM.using(salt, costParameter, blocksize, parallelizationParam,
                                Strings.toUTF8ByteArray(password)));
        byte[] output = new byte[32];
        calculator.generateBytes(output);
        return output;
    }
}
