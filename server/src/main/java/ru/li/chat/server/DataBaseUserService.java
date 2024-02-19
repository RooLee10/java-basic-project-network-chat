package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
    static class User {
        private String username;
        private final String login;
        private final String password;
        private final String salt;
        private OffsetDateTime banTime;
        private Set<UserRole> roles;

        public User(String username, String login, String password, String salt, Set<UserRole> roles) {
            this.username = username;
            this.login = login;
            this.password = password;
            this.salt = salt;
            this.roles = roles;
        }

        public User(String username, String login, String password, String salt, OffsetDateTime banTime, Set<UserRole> roles) {
            this.username = username;
            this.login = login;
            this.password = password;
            this.salt = salt;
            this.banTime = banTime;
            this.roles = roles;
        }

        @Override
        public String toString() {
            return "User{" +
                    ", username='" + username + '\'' +
                    ", login='" + login + '\'' +
                    ", banTime='" + banTime + '\'' +
                    ", roles=" + roles +
                    '}';
        }
    }

    DataSource dataSource;
    private final List<User> users;
    private final Logger logger = LogManager.getLogger(DataBaseUserService.class.getName());

    public DataBaseUserService() throws SQLException {
        this.dataSource = new DataSource();
        this.users = new ArrayList<>();
        fillUsers();
    }

    private void fillUsers() {
        String sqlQuery = "SELECT u.user_id, u.user_name, u.login, u.password, u.salt, u.ban_time, r.role_name FROM UserToRole utr JOIN Users u ON utr.user_id = u.user_id JOIN Roles r ON utr.role_id = r.role_id";
        logger.debug("fillUsers - получение результата запроса: " + sqlQuery);
        try (ResultSet resultSet = dataSource.getStatement().executeQuery(sqlQuery)) {
            Map<Integer, User> idToUsersData = new HashMap<>(); // Для сохранения данных о пользователях
            Map<Integer, Set<UserRole>> idToRole = new HashMap<>(); // Для сохранения ролей пользователей
            while (resultSet.next()) {
                int userId = resultSet.getInt(1);
                String userName = resultSet.getString(2);
                String login = resultSet.getString(3);
                String password = resultSet.getString(4);
                String salt = resultSet.getString(5);
                OffsetDateTime banTime = resultSet.getObject(6, OffsetDateTime.class);
                String roleName = resultSet.getString(7);
                // Данные о пользователях
                if (!idToUsersData.containsKey(userId)) {
                    User user = new User(userName, login, password, salt, banTime, new HashSet<>());
                    idToUsersData.put(userId, user);
                    logger.debug("fillUsers - создался пользователь: " + user);
                }
                // Данные о ролях
                if (idToRole.containsKey(userId)) {
                    Set<UserRole> userRoles = idToRole.get(userId);
                    userRoles.add(UserRole.valueOf(roleName));
                } else {
                    Set<UserRole> userRoles = new HashSet<>();
                    userRoles.add(UserRole.valueOf(roleName));
                    idToRole.put(userId, userRoles);
                }
            }
            // Обработаем случай первого запуска, если ещё нет пользователей, то создадим admin/admin
            if (idToUsersData.isEmpty()) {
                createNewUser("admin", "admin", getDefaultPasswordForAdmin(), UserRole.ADMIN);
                fillUsers(); // рекурсивно вызовем для получения данных
            }
            // Заполним роли
            for (int userId : idToUsersData.keySet()) {
                User user = idToUsersData.get(userId);
                user.roles = idToRole.getOrDefault(userId, new HashSet<>());
                this.users.add(user);
                logger.debug("fillUsers - заполнились роли: " + user);
            }
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getUsernameByLoginAndPassword(String login, String password) {
        User userByLogin = null;
        for (User user : users) {
            if (user.login.equals(login)) {
                userByLogin = user;
                break;
            }
        }
        if (userByLogin == null) {
            return null;
        }
        byte[] salt = decodeToByteArray(userByLogin.salt);
        String hashedPassword = getHashString(password, salt);
        if (userByLogin.password.equals(hashedPassword)) {
            return userByLogin.username;
        }
        return null;
    }

    @Override
    public String getUserInfo(String username) {
        return getUserByUsername(username).toString();
    }

    @Override
    public OffsetDateTime getUserBanTime(String username) {
        User user = getUserByUsername(username);
        return user.banTime;
    }

    @Override
    public boolean isUsernameExists(String username) {
        for (User user : users) {
            if (user.username.equals(username)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isLoginAlreadyExists(String login) {
        for (User user : users) {
            if (user.login.equals(login)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isUserAdmin(String username) {
        for (User user : users) {
            if (user.username.equals(username) && user.roles.contains(UserRole.ADMIN)) {
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
        logger.debug("createNewUser - подключение к базе данных");
        try {
            Connection connection = dataSource.getConnection();
            connection.setAutoCommit(false);
            insertIntoUsers(username, login, hashedPassword, saltString);
            insertIntoUserToRole(login, role.toString());
            connection.setAutoCommit(true);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        User user = new User(username, login, hashedPassword, saltString, new HashSet<>(List.of(role)));
        this.users.add(user);
        logger.info("Зарегистрирован новый пользователь: " + user);
    }

    private void insertIntoUserToRole(String login, String roleName) throws SQLException {
        int userId = getUserIdByLogin(login);
        int roleId = getRoleIdByRoleName(roleName);
        try {
            PreparedStatement preparedStatement = dataSource.getPreparedStatementInsertIntoUserToRole();
            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, roleId);
            logger.debug("insertIntoUserToRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private void insertIntoUsers(String username, String login, String password, String salt) throws SQLException {
        try {
            PreparedStatement preparedStatement = dataSource.getPreparedStatementInsertIntoUsers();
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, login);
            preparedStatement.setString(3, password);
            preparedStatement.setString(4, salt);
            logger.debug("insertIntoUsers - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private int getRoleIdByRoleName(String roleName) throws SQLException {
        PreparedStatement preparedStatement = dataSource.getPreparedStatementGetRoleIdByRoleName();
        preparedStatement.setString(1, roleName);
        try (ResultSet resultSet = preparedStatement.executeQuery()) {
            if (!resultSet.next()) {
                createNewRole(roleName);
                return getRoleIdByRoleName(roleName);
            }
            return resultSet.getInt(1);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private void createNewRole(String roleName) throws SQLException {
        PreparedStatement preparedStatement = dataSource.getPreparedStatementCreateNewRole();
        preparedStatement.setString(1, roleName);
        preparedStatement.executeUpdate();
    }

    private int getUserIdByLogin(String login) throws SQLException {
        PreparedStatement preparedStatement = dataSource.getPreparedStatementGetUserIdByLogin();
        preparedStatement.setString(1, login);
        try (ResultSet resultSet = preparedStatement.executeQuery()) {
            resultSet.next();
            return resultSet.getInt(1);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    @Override
    public void addRole(String username, String roleName) {
        User user = getUserByUsername(username);
        try {
            insertIntoUserToRole(user.login, roleName);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.roles.add(UserRole.valueOf(roleName));
    }

    @Override
    public void removeRole(String username, String roleName) {
        User user = getUserByUsername(username);
        try {
            deleteFromUserToRole(user.login, roleName);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.roles.remove(UserRole.valueOf(roleName));
    }

    private void deleteFromUserToRole(String login, String roleName) throws SQLException {
        int userId = getUserIdByLogin(login);
        int roleId = getRoleIdByRoleName(roleName);
        PreparedStatement preparedStatement = dataSource.getPreparedStatementDeleteFromUserToRole();
        preparedStatement.setInt(1, userId);
        preparedStatement.setInt(2, roleId);
        logger.debug("deleteFromUserToRole - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    @Override
    public void changeUsername(String currentUsername, String newUsername) {
        User currentUser = getUserByUsername(currentUsername);
        changeUsernameInDataBase(currentUser.login, newUsername);
        currentUser.username = newUsername;
    }

    @Override
    public void banUser(String username, OffsetDateTime banTime) {
        User user = getUserByUsername(username);
        logger.debug("banUser - подключение к базе данных");
        try {
            int userId = getUserIdByLogin(user.login);
            updateUserBanTime(userId, banTime);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.banTime = banTime;
    }

    private void updateUserBanTime(int userId, OffsetDateTime banTime) throws SQLException {
        PreparedStatement preparedStatement = dataSource.getPreparedStatementUpdateUserBanTime();
        preparedStatement.setObject(1, banTime);
        preparedStatement.setInt(2, userId);
        logger.debug("updateUserBanTime - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    @Override
    public boolean isUserHasRole(String username, String roleName) {
        User user = getUserByUsername(username);
        return user.roles.contains(UserRole.valueOf(roleName));
    }

    @Override
    public boolean isUserHasOneRole(String username) {
        User user = getUserByUsername(username);
        return user.roles.size() == 1;
    }

    @Override
    public boolean isUserLastAdmin(String username) {
        for (User user : users) {
            if (user.roles.contains(UserRole.ADMIN) && !user.username.equals(username)) {
                return false;
            }
        }
        return true;
    }

    private void changeUsernameInDataBase(String login, String newUsername) {
        try {
            int userId = getUserIdByLogin(login);
            setNewUsernameByUserId(userId, newUsername);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void setNewUsernameByUserId(int userId, String newUsername) throws SQLException {
        PreparedStatement preparedStatement = dataSource.getPreparedStatementSetNewUsernameByUserId();
        preparedStatement.setString(1, newUsername);
        preparedStatement.setInt(2, userId);
        logger.debug("setNewUsernameByUserId - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    private User getUserByUsername(String username) {
        User result = null;
        for (User user : users) {
            if (user.username.equals(username)) {
                result = user;
                break;
            }
        }
        if (result == null) {
            logger.error("Не найден пользователь по имени: " + username);
            throw new RuntimeException("Не найден пользователь по имени: " + username);
        }
        return result;
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
