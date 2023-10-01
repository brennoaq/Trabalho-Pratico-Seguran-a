package maven2fa;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.encoders.DecoderException;

import java.io.*;
import java.util.HashMap;

import static maven2fa.Utils.*;
import static maven2fa.SCRYPT.generateSalt;

public class PersistData {
    public static HashMap<String, User> users = new HashMap<>();
    public static final HashMap<String, HashMap<String, String>> messages = new HashMap<>();
    private static final String usersFile = "Users.txt";

    public static void registerUser(String username, String phoneNumber, String password) throws Exception {
        if (username == null || phoneNumber == null || password == null) {
            System.out.println("Dados inválidos. Tente novamente.");
            return;
        }

        if (users.containsKey(username)) {
            System.out.println("Usuário já existe. Escolha outro nome de usuário.");
            return;
        }

        byte[] salt = generateSalt();  // Método para gerar um salt aleatório
        int costParameter = 2048; // exemplo: 2048 (afeta uso de memória e CPU)
        int blocksize = 8; // exemplo: 8
        int parallelizationParam = 1; // exemplo: 1

        byte[] hashPassword = SCRYPT.useScryptKDF(password.toCharArray(), salt, costParameter, blocksize, parallelizationParam);
        String scryptHashPassword = Hex.encodeHexString(hashPassword);

        byte[] derivateKey = CypherSecurity.deriveKeyOrIV(phoneNumber, salt, false); // derivado usando PBKDF2 (HASH)

        String PBKDF2asString = convertBase32(derivateKey); // get string

        String email = "ine5680@ufsc.br";
        String companyName = "seguranca";
        String googleAuthenticatorBarCode = getGoogleAuthenticatorBarCode(PBKDF2asString, email, companyName);
        System.out.println("GA Token = " + googleAuthenticatorBarCode);

        // Fica no diretório do projeto.
        createQRCode(googleAuthenticatorBarCode, "GA_Key.png", 246, 246);
        System.out.println("Com um leitor de QR Code, leia no diretorio raiz do projeto o arquivo GA_Key.png para salvar o segredo no Google Auth");

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPhoneNumber(phoneNumber);
        newUser.setPassword(scryptHashPassword);
        newUser.setSalt(salt);

        users.put(username, newUser);
        persist();
    }

    public static void persist() {
        try {
            File file = new File(usersFile);
            boolean isNewFile = file.createNewFile(); // Retorna true se o arquivo foi criado, false se já existir

            BufferedWriter writer = new BufferedWriter(new FileWriter(file, true)); // true para adicionar ao final do arquivo existente

            // Escreva o cabeçalho da tabela apenas se for um novo arquivo
            if (isNewFile) {
                writer.write("nome ; celular ; senha ; salt\n");
            }

            // Escreva os detalhes de cada usuário na tabela
            for (User user : users.values()) {
                writer.write(user.getUsername() + ";");
                writer.write(user.getPhoneNumber() + ";");
                writer.write(user.getPassword() + ";");
                writer.write(Hex.encodeHexString(user.getSalt()) + "\n"); // Converta o salt para uma string hexadecimal
            }

            writer.flush();
            writer.close();

        } catch (FileNotFoundException ex) {
            System.out.println("Erro: Arquivo não encontrado. Criando novo arquivo...");
            persist(); // Chame persist novamente após criar o arquivo
        } catch (IOException ex) {
            System.out.println("Erro de IO: " + ex.getMessage());
        }
    }

    public static void loadData() {
        users.clear(); // Limpe o mapa atual de usuários

        try {
            BufferedReader reader = new BufferedReader(new FileReader(usersFile));

            String line;
            boolean isFirstLine = true; // Para ignorar a primeira linha (cabeçalho)

            while ((line = reader.readLine()) != null) {
                if (isFirstLine) {
                    isFirstLine = false;
                    continue; // Ignora o cabeçalho
                }

                String[] parts = line.split(";");
                if (parts.length != 4) {
                    System.out.println("Linha mal formatada: " + line);
                    continue;
                }

                User user = new User();
                user.setUsername(parts[0]);
                user.setPhoneNumber(parts[1]);
                user.setPassword(parts[2]);
                try {
                    user.setSalt(Hex.decodeHex(parts[3].toCharArray())); // Converta a string hexadecimal de volta para um array de bytes
                } catch (DecoderException ex) {
                    System.out.println("Erro ao decodificar o salt para o usuário " + parts[0] + ": " + ex.getMessage());
                    continue; // Ignora este usuário e passa para o próximo
                }

                users.put(user.getUsername(), user);
            }

            reader.close();

        } catch (FileNotFoundException ex) {
            System.out.println("Erro: Arquivo não encontrado.");
        } catch (IOException ex) {
            System.out.println("Erro de IO: " + ex.getMessage());
        } catch (DecoderException ex) {
            System.out.println("Erro ao decodificar o salt: " + ex.getMessage());
        } catch (org.apache.commons.codec.DecoderException e) {
            throw new RuntimeException(e);
        }
    }

}
