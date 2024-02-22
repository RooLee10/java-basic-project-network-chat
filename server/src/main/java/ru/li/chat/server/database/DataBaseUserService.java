package ru.li.chat.server.database;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.User;
import ru.li.chat.server.UserRole;
import ru.li.chat.server.UserService;
import ru.li.chat.server.dao.UsersDao;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.*;
import java.time.OffsetDateTime;
import java.util.*;

public class DataBaseUserService implements UserService {
    private List<User> users;
    private final Logger logger = LogManager.getLogger(DataBaseUserService.class.getName());

    public DataBaseUserService() {
        this.users = UsersDao.getAllUsersData();
        if (this.users.isEmpty()) {
            // Обработаем случай первого запуска, если ещё нет пользователей, то создадим admin/admin
            createNewUser("admin", "admin", getDefaultPasswordForAdmin(), UserRole.ADMIN);
            this.users = UsersDao.getAllUsersData();
        }
    }

    @Override
    public String getUsernameByLoginAndPassword(String login, String password) {
        User userByLogin = null;
        for (User user : users) {
            if (user.getLogin().equals(login)) {
                userByLogin = user;
                break;
            }
        }
        if (userByLogin == null) {
            return null;
        }
        byte[] salt = decodeToByteArray(userByLogin.getSalt());
        String hashedPassword = getHashString(password, salt);
        if (userByLogin.getPassword().equals(hashedPassword)) {
            return userByLogin.getUsername();
        }
        return null;
    }

    @Override
    public String getUserInfo(String username) {
        return getUserByUsername(username).toString();
    }

    @Override
    public OffsetDateTime getUserBanTime(String username) {
        return getUserByUsername(username).getBanTime();
    }

    @Override
    public boolean isUsernameExists(String username) {
        for (User user : users) {
            if (user.getUsername().equals(username)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isLoginAlreadyExists(String login) {
        for (User user : users) {
            if (user.getLogin().equals(login)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isUserAdmin(String username) {
        for (User user : users) {
            if (user.getUsername().equals(username) && user.getRoles().contains(UserRole.ADMIN)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void createNewUser(String username, String login, String password, UserRole role) {
        byte[] salt = getSalt();
        String saltString = encodeToString(salt);
        String hashedPassword = getHashString(password, salt);
        User user = UsersDao.createNewUser(username, login, hashedPassword, saltString, role);
        this.users.add(user);
        logger.info("Зарегистрирован новый пользователь: " + user);
    }

    @Override
    public void addRole(String username, String roleName) {
        User user = getUserByUsername(username);
        try {
            UsersDao.insertIntoUserToRole(user.getLogin(), roleName);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.addRole(UserRole.valueOf(roleName));
    }

    @Override
    public void removeRole(String username, String roleName) {
        User user = getUserByUsername(username);
        try {
            UsersDao.deleteFromUserToRole(user.getLogin(), roleName);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.removeRole(UserRole.valueOf(roleName));
    }

    @Override
    public void changeUsername(String currentUsername, String newUsername) {
        User currentUser = getUserByUsername(currentUsername);
        UsersDao.changeUsernameInDataBase(currentUser.getLogin(), newUsername);
        currentUser.setUsername(newUsername);
    }

    @Override
    public void banUser(String username, OffsetDateTime banTime) {
        User user = getUserByUsername(username);
        try {
            int userId = UsersDao.getUserIdByLogin(user.getLogin());
            UsersDao.updateUserBanTime(userId, banTime);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.setBanTime(banTime);
    }

    @Override
    public boolean isUserHasRole(String username, String roleName) {
        User user = getUserByUsername(username);
        return user.getRoles().contains(UserRole.valueOf(roleName));
    }

    @Override
    public boolean isUserHasOneRole(String username) {
        User user = getUserByUsername(username);
        return user.getRoles().size() == 1;
    }

    @Override
    public boolean isUserLastAdmin(String username) {
        for (User user : users) {
            if (user.getRoles().contains(UserRole.ADMIN) && !user.getUsername().equals(username)) {
                return false;
            }
        }
        return true;
    }

    private User getUserByUsername(String username) {
        for (User user : users) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        logger.error("Не найден пользователь по имени: " + username);
        throw new RuntimeException("Не найден пользователь по имени: " + username);
    }

    private byte[] getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private String getDefaultPasswordForAdmin() {
        // Нужна только для создания первого пользователя admin/admin
        // Чтобы пользователь потом мог войти, так как с клиента летит хешированный (этой же солью) пароль
        byte[] fixedSalt = "My unique fixed salt".getBytes();
        byte[] hash = getHash("admin", fixedSalt);
        return encodeToString(hash);
    }

    private byte[] getHash(String password, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private String getHashString(String password, byte[] salt) {
        byte[] hash = getHash(password, salt);
        return encodeToString(hash);
    }

    private String encodeToString(byte[] data) {
        return Base64.getEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] decodeToByteArray(String data) {
        return Base64.getDecoder().decode(data);
    }
}
