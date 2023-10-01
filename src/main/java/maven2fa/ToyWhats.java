package maven2fa;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.encoders.DecoderException;

import java.io.*;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import static maven2fa.Example2fa.*;
import static maven2fa.SCRYPT.generateSalt;

public class ToyWhats {
    public HashMap<String, User> users = new HashMap<>();
    private final HashMap<String, HashMap<String, String>> messages = new HashMap<>();
    private final String usersFile = "Users.txt";

    public void registerUser(String username, String phoneNumber, String password) throws Exception {
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
        String scryptHashPassword =  Hex.encodeHexString(hashPassword);

        byte[] derivateKey = deriveKey(phoneNumber, salt); // derivado usando PBKDF2 (HASH)

        String PBKDF2asString = convertBase32(derivateKey); // get string

        String email = "email@gmail.com";
        String companyName = "Empresa";
        String barCodeUrl = getGoogleAuthenticatorBarCode(PBKDF2asString, email, companyName);
        System.out.println("Bar Code URL = " + barCodeUrl);

        int width = 246;
        int height = 246;

        // Fica no diretório do projeto.
        createQRCode(barCodeUrl, "matrixURL.png", height, width);

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPhoneNumber(phoneNumber);
        newUser.setPassword(scryptHashPassword);
        newUser.setSalt(salt);

        users.put(username, newUser);
        this.persist();
    }



    public boolean authenticateUser(String username, String password, String totpCode) throws Exception {

//          String TOTPcode = getTOTPCode(PBKDF2asString); // TOTP code
        // Carregue os dados do arquivo para o mapa de usuários
        loadData();

        if (username == null || password == null || totpCode == null) {
            System.out.println("Dados inválidos. Tente novamente.");
            return false;
        }

        User user = users.get(username);
        if (user == null) {
            System.out.println("Usuário não encontrado.");
            return false;
        }

        byte[] storedSalt = user.getSalt();
        int costParameter = 2048; // exemplo: 2048 (afeta uso de memória e CPU)
        int blocksize = 8; // exemplo: 8
        int parallelizationParam = 1; // exemplo: 1

        byte[] derivedKey2 = SCRYPT.useScryptKDF(password.toCharArray(), storedSalt, costParameter, blocksize, parallelizationParam);
        String ScryptPassword =  Hex.encodeHexString(derivedKey2);

        String storedDerivedKey = user.getPassword();

        return ScryptPassword.equals(storedDerivedKey) && totpCode.equals(getTOTPCode(user.getSecretKey()));
    }

    public void sendMessage(String fromUser, String toUser, String message) {
        try {
            // Validação básica
            if (fromUser == null || toUser == null || message == null) {
                System.out.println("Dados inválidos. Tente novamente.");
                return;
            }

            // Verificar se os usuários existem
            if (!users.containsKey(fromUser) || !users.containsKey(toUser)) {
                System.out.println("Usuário não encontrado.");
                return;
            }

            // Obter a chave secreta do usuário de origem
            String key = users.get(fromUser).getSecretKey();
            if (key == null) {
                System.out.println("Chave secreta não encontrada para o usuário de origem.");
                return;
            }


            // Criptografar a mensagem
            byte[] encryptedMessage = encryptMessage(message, key);

            // Converter para Base64 para armazenamento seguro como string
            String encryptedMessageStr = Base64.getEncoder().encodeToString(encryptedMessage);

            // Armazenar a mensagem criptografada
            messages.computeIfAbsent(fromUser, k -> new HashMap<>()).put(toUser, encryptedMessageStr);
        } catch (Exception e) {
            System.out.println("Erro ao enviar mensagem: " + e.getMessage());
        }
    }

    public String readMessage(String fromUser, String toUser) {
        try {
            if (fromUser == null || toUser == null) {
                System.out.println("Dados inválidos. Tente novamente.");
                return null;
            }

            if (!users.containsKey(fromUser) || !users.containsKey(toUser)) {
                System.out.println("Usuário não encontrado.");
                return null;
            }

            User fromUserObj = users.get(fromUser);
            if (fromUserObj == null) {
                System.out.println("Usuário de origem não encontrado.");
                return null;
            }

            String key = fromUserObj.getSecretKey(); // Usando a secret key do usuário como chave de decifragem
            if (key == null) {
                System.out.println("Chave secreta não encontrada para o usuário de origem.");
                return null;
            }

            HashMap<String, String> fromUserMessages = messages.get(fromUser);
            if (fromUserMessages == null) {
                System.out.println("Nenhuma mensagem encontrada para o usuário de origem.");
                return null;
            }

            String encryptedMessageStr = fromUserMessages.get(toUser);
            if (encryptedMessageStr == null) {
                System.out.println("Nenhuma mensagem encontrada para o usuário destino.");
                return null;
            }

            byte[] encryptedMessage = encryptedMessageStr.getBytes(); // Convertendo de volta para bytes
            return decryptMessage(encryptedMessage, key);
        } catch (Exception e) {

            System.out.println("Erro ao ler mensagem: " + e.getMessage());
            return null;
        }
    }

    // menu usuario altenticado
    public void postAuthenticationMenu(String authenticatedUser) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("1 - Enviar Mensagem");
            System.out.println("2 - Ler Mensagens");
            System.out.println("3 - Sair da Sessão");
            String option = scanner.nextLine();

            switch (option) {
                case "1":
                    System.out.println("Insira o nome do usuário para enviar a mensagem:");
                    String toUser = scanner.nextLine();
                    System.out.println("Insira a mensagem:");
                    String message = scanner.nextLine();
                    sendMessage(authenticatedUser, toUser, message);
                    break;
                case "2":
                    System.out.println("Insira o nome do usuário para ler as mensagens:");
                    String fromUser = scanner.nextLine();
                    String receivedMessage = readMessage(fromUser, authenticatedUser);
                    System.out.println("Mensagem recebida: " + receivedMessage);
                    break;
                case "3":
                    System.out.println("Saindo da sessão...");
                    return;
                default:
                    System.out.println("Opção inválida. Tente novamente.");
            }
        }
    }

    public byte[] encryptMessage(String message, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        // Gerar um IV aleatório
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12]; // GCM 12 bytes para o IV
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] encryptedText = cipher.doFinal(message.getBytes());

        // Concatenar IV e texto cifrado para armazenamento
        byte[] encryptedMessage = new byte[iv.length + encryptedText.length];
        System.arraycopy(iv, 0, encryptedMessage, 0, iv.length);
        System.arraycopy(encryptedText, 0, encryptedMessage, iv.length, encryptedText.length);

        return encryptedMessage;
    }

    public String decryptMessage(byte[] encryptedMessageWithIv, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        // Extrair IV e texto cifrado
        byte[] iv = new byte[12];
        System.arraycopy(encryptedMessageWithIv, 0, iv, 0, iv.length);
        byte[] encryptedText = new byte[encryptedMessageWithIv.length - iv.length];
        System.arraycopy(encryptedMessageWithIv, iv.length, encryptedText, 0, encryptedText.length);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] decryptedMessage = cipher.doFinal(encryptedText);

        return new String(decryptedMessage);
    }

    public static byte[] deriveKey(String phone, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(phone.toCharArray(), salt, 65536, 160);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return key;
    }

    public void persist() {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(usersFile, false)); // false para sobrescrever o arquivo existente

            // Escreva o cabeçalho da tabela
            writer.write("nome;celular;senha;salt\n");

            // Escreva os detalhes de cada usuário na tabela
            for (User user : users.values()) {
                writer.write(user.getUsername() + ";");
                writer.write(user.getPhoneNumber() + ";");
                writer.write(user.getPassword() + ";");
                writer.write(Hex.encodeHexString(user.getSalt()) + "\n"); // Converta o salt para uma string hexadecimal
            }

            writer.flush();
            writer.close();

        }  catch (FileNotFoundException ex) {
            System.out.println("Erro: Arquivo não encontrado. Criando novo arquivo...");
            File file = new File(usersFile);
            try {
                if (file.createNewFile()) {
                    persist(); // Chame persist novamente após criar o arquivo
                } else {
                    System.out.println("Erro ao criar o arquivo. Verifique as permissões e tente novamente.");
                }
            } catch (IOException e) {
                System.out.println("Erro ao criar o arquivo: " + e.getMessage());
            }
        } catch (IOException ex) {
            System.out.println("Erro de IO: " + ex.getMessage());
        }
    }

    public void loadData() {
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
                user.setSalt(Hex.decodeHex(parts[3].toCharArray())); // Converta a string hexadecimal de volta para um array de bytes

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
