package maven2fa;

import org.apache.commons.codec.binary.Hex;

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

        byte[] derivedKey = SCRYPT.useScryptKDF(password.toCharArray(), salt, costParameter, blocksize, parallelizationParam);
        String ScryptPassword =  Hex.encodeHexString(derivedKey);

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPhoneNumber(phoneNumber);
        newUser.setPassword(ScryptPassword);
        newUser.setSalt(salt);
        newUser.setSecretKey(Example2fa.generateSecretKey()); //gera chave 2FA para o user

        users.put(username, newUser);
        this.persist();
    }



    public boolean authenticateUser(String username, String password, String totpCode) throws Exception {
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

        return ScryptPassword.equals(storedDerivedKey) && totpCode.equals(Example2fa.getTOTPCode(user.getSecretKey()));
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

    public static String deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new String(key);
    }

    public void persist() {
        try {
            FileOutputStream fout = new FileOutputStream(usersFile);
            ObjectOutputStream oo = new ObjectOutputStream(fout);
            oo.writeObject(this.users);

            oo.flush();
            fout.flush();

            oo.close();
            fout.close();

            loadData();

        } catch (FileNotFoundException ex) {
            System.out.println(ex);
            persist();
        } catch (IOException ex) {
            System.out.println(ex);
        }
    }

    public void loadData() {
        try {
            FileInputStream fin = new FileInputStream(usersFile);
            ObjectInputStream oi = new ObjectInputStream(fin);

            this.users = (HashMap<String, User>) oi.readObject();

            oi.close();
            fin.close();

        } catch (ClassNotFoundException ex) {
            ex.printStackTrace();

        } catch (FileNotFoundException ex) {
            System.out.println(ex);
            persist();

        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
