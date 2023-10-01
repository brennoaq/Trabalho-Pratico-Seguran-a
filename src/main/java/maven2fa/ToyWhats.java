package maven2fa;

import org.apache.commons.codec.binary.Hex;

import java.util.HashMap;
import java.util.Base64;
import java.util.Scanner;

import static maven2fa.CypherSecurity.deriveKeyOrIV;
import static maven2fa.Utils.*;

public class ToyWhats {

    public boolean authenticateUser(String username, String password, String totpCode) throws Exception {

        // Carregue os dados do arquivo para o mapa de usuários
        PersistData.loadData();

        if (username == null || password == null || totpCode == null) {
            System.out.println("Dados inválidos. Tente novamente.");
            return false;
        }

        User user = PersistData.users.get(username);
        if (user == null) {
            System.out.println("Usuário não encontrado.");
            return false;
        }

        byte[] storedSalt = user.getSalt();
        int costParameter = 2048; // exemplo: 2048 (afeta uso de memória e CPU)
        int blocksize = 8; // exemplo: 8
        int parallelizationParam = 1; // exemplo: 1

        byte[] derivedKey2 = SCRYPT.useScryptKDF(password.toCharArray(), storedSalt, costParameter, blocksize, parallelizationParam);
        String ScryptPassword = Hex.encodeHexString(derivedKey2);

        String storedDerivedKey = user.getPassword();
        byte[] derivateKey = deriveKeyOrIV(user.getPhoneNumber(), user.getSalt(), false); // derivado usando PBKDF2 (HASH)
        String PBKDF2asString = convertBase32(derivateKey);

        return ScryptPassword.equals(storedDerivedKey) && totpCode.equals(getTOTPCode(PBKDF2asString));
    }

    public void sendMessage(String senderName, String receiverName, String message) {
        try {
            // Validação básica
            if (senderName == null || receiverName == null || message == null) {
                System.out.println("Dados inválidos. Tente novamente.");
                return;
            }

            // Verificar se os usuários existem
            if (!PersistData.users.containsKey(senderName) || !PersistData.users.containsKey(receiverName)) {
                System.out.println("Usuário não encontrado.");
                return;
            }

            User user = PersistData.users.get(senderName);
            String phone = user.getPhoneNumber();
            byte[] salt = user.getSalt();

            byte[] derivateKey = deriveKeyOrIV(phone, salt, false);
            String PBKDF2Key = convertBase32(derivateKey);

            // Obter a chave secreta do usuário de origem
            if (PBKDF2Key == null) {
                System.out.println("Chave secreta não encontrada para o usuário de origem.");
                return;
            }

            // Criptografar a mensagem
            byte[] encryptedMessage = CypherSecurity.encryptMessage(message, phone, PBKDF2Key, salt);

            // Converter para Base64 para armazenamento seguro como string
            String encryptedMessageStr = Base64.getEncoder().encodeToString(encryptedMessage);

            // Print
            System.out.println("MENSAGEM CIFRADA: " + encryptedMessageStr);

            // Armazenar a mensagem criptografada
            PersistData.messages.computeIfAbsent(senderName, k -> new HashMap<>()).put(receiverName, encryptedMessageStr);

            System.out.println("Mensagem Cifrada Enviada!");
        } catch (Exception e) {
            System.out.println("Erro ao enviar mensagem: " + e.getMessage());
        }
    }

    public String readMessage(String senderUser, String receiverUser) {
        try {
            if (senderUser == null || receiverUser == null) {
                System.out.println("Dados inválidos. Tente novamente.");
                return null;
            }

            if (!PersistData.users.containsKey(senderUser) || !PersistData.users.containsKey(receiverUser)) {
                System.out.println("Usuário não encontrado.");
                return null;
            }

            User fromUserObj = PersistData.users.get(senderUser);
            if (fromUserObj == null) {
                System.out.println("Usuário de origem não encontrado.");
                return null;
            }

            byte[] derivateKey = deriveKeyOrIV(fromUserObj.getPhoneNumber(), fromUserObj.getSalt(), false);
            String PBKDF2Key = convertBase32(derivateKey);

            if (PBKDF2Key == null) {
                System.out.println("Chave secreta não encontrada para o usuário de origem.");
                return null;
            }

            HashMap<String, String> fromUserMessages = PersistData.messages.get(senderUser);
            if (fromUserMessages == null) {
                System.out.println("Nenhuma mensagem encontrada para o usuário de origem.");
                return null;
            }

            String encryptedMessageStr = fromUserMessages.get(receiverUser);
            if (encryptedMessageStr == null) {
                System.out.println("Nenhuma mensagem encontrada para o usuário destino.");
                return null;
            }


            byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageStr.getBytes()); // Convertendo de volta para bytes

            return CypherSecurity.decryptMessage(encryptedMessage, PBKDF2Key);
        } catch (Exception e) {

            System.out.println("Erro ao ler mensagem: " + e.getMessage());
            return null;
        }
    }

    // menu usuario autenticado
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

}
