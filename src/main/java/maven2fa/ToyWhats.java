package maven2fa;

import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class ToyWhats {
    public final HashMap<String, User> users = new HashMap<>();
    private final HashMap<String, HashMap<String, String>> messages = new HashMap<>();

    public void registerUser(String username, String phoneNumber, String password) throws Exception {
        if (username == null || phoneNumber == null || password == null) {
            System.out.println("Dados inválidos. Tente novamente.");
            return;
        }

        if (users.containsKey(username)) {
            System.out.println("Usuário já existe. Escolha outro nome de usuário.");
            return;
        }

        String salt = generateSalt();  // Método para gerar um salt aleatório
        String derivedKey = deriveKey(password, salt);  // Usando PBKDF2 para derivar a chave

        User newUser = new User();
        newUser.setUsername(username);
        newUser.setPhoneNumber(phoneNumber);
        newUser.setPassword(derivedKey);
        newUser.setSalt(salt);
        newUser.setSecretKey(Example2fa.generateSecretKey()); //gera chave 2FA para o user

        users.put(username, newUser);
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

        String storedSalt = user.getSalt();
        String storedDerivedKey = user.getPassword();
        String derivedKey = deriveKey(password, storedSalt);

        return derivedKey.equals(storedDerivedKey) && totpCode.equals(Example2fa.getTOTPCode(user.getSecretKey()));
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

    public static String deriveKey(String password, String salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 128);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] key = skf.generateSecret(spec).getEncoded();
        return new String(key);
    }

    // Gerando um salt aleatorio
    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}
