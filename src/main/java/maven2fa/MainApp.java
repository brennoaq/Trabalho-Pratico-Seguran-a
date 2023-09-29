package maven2fa;

import com.google.zxing.WriterException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MainApp {
    public static void main(String args[]) {
        try {
            ToyWhats toyWhats = new ToyWhats();
            Scanner scanner = new Scanner(System.in);
            while (true) {
                System.out.println("1 - Cadastrar Novo Usuário");
                System.out.println("2 - Fazer Login");
                System.out.println("3 - Sair");
                String option = scanner.nextLine();

                switch (option) {
                    case "1":
                        System.out.println("Insira o login:");
                        String login = scanner.nextLine();
                        System.out.println("Insira o celular:");
                        String celular = scanner.nextLine();
                        System.out.println("Insira a senha:");
                        String password = scanner.nextLine();
                        toyWhats.registerUser(login, celular, password);

                        User user = toyWhats.users.get(login);
                        String secret = user.getSecretKey();

                        System.out.println("Chave secreta para 2FA: " + secret);
                        System.out.println("=====cadastro========concluido===== ");
                        break;
                    case "2":
                        System.out.println("Insira o login:");
                        String loginToAuth = scanner.nextLine();
                        System.out.println("Insira a senha:");
                        String passwordToAuth = scanner.nextLine();
                        System.out.println("Insira o código TOTP:");
                        String totpCode = scanner.nextLine();
                        boolean isAuthenticated = toyWhats.authenticateUser(loginToAuth, passwordToAuth, totpCode);

                        if (isAuthenticated) {
                            System.out.println("Usuário autenticado.");
                            toyWhats.postAuthenticationMenu(loginToAuth);
                        } else {
                            System.out.println("Falha na autenticação. Tente novamente.");
                        }
                        break;
                    case "3":
                        System.out.println("Saindo...");
                        System.exit(0);
                    default:
                        System.out.println("Opção inválida. Tente novamente.");
                }
            }

        } catch (WriterException ex) {
            Logger.getLogger(Example2fa.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Example2fa.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

