package ru.li.chat.server.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.User;
import ru.li.chat.server.UserRole;
import ru.li.chat.server.database.DataSource;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.*;
import java.time.OffsetDateTime;
import java.util.*;

public class UsersDao {
    private static Logger logger = LogManager.getLogger(UsersDao.class.getName());
    private static final String SQL_UPDATE_USERS_SET_BAN_TIME = "UPDATE Users SET ban_time = ? WHERE user_id = ?";
    private static final String SQL_UPDATE_USERS_SET_USERNAME = "UPDATE Users SET user_name = ? WHERE user_id = ?";
    private static final String SQL_SELECT_USER_ID_FROM_USERS_BY_LOGIN = "SELECT u.user_id FROM Users u WHERE u.login = ?";
    private static final String SQL_DELETE_FROM_USER_TO_ROLE = "DELETE FROM UserToRole WHERE user_id = ? and role_id = ?";
    private static final String SQL_SELECT_ALL_USERS_DATA = "SELECT u.user_id, u.user_name, u.login, u.password, u.salt, u.ban_time, r.role_name FROM UserToRole utr JOIN Users u ON utr.user_id = u.user_id JOIN Roles r ON utr.role_id = r.role_id";
    private static final String SQL_INSERT_INTO_USERS = "INSERT INTO Users (user_name, login, password, salt) values (?, ?, ?, ?)";
    private static final String SQL_INSERT_INTO_USER_TO_ROLE = "INSERT INTO UserToRole (user_id, role_id) values (?, ?)";

    private static Map<String, User> usersByLogin = new HashMap<>();
    private static Map<String, User> usersByUsername = new HashMap<>();

    static {
        getAllUsersData();
        if (usersByLogin.isEmpty()) {
            createDefaultAdmin();
            getAllUsersData();
        }
    }

    public static void createNewUser(String username, String login, String password, UserRole role) {
        byte[] salt = getSalt();
        String saltString = encodeToString(salt);
        String hashedPassword = getHashString(password, salt);
        try (Connection connection = DataSource.getConnection()) {
            logger.debug(String.format("createNewUser %s", connection));

            connection.setAutoCommit(false);
            insertIntoUsers(username, login, hashedPassword, saltString, connection);
            int userId = getUserIdByLoginFromDB(login, connection);
            int roleId = RolesDao.getRoleId(role);
            insertIntoUserToRole(userId, roleId, connection);
            connection.setAutoCommit(true);

            User user = new User(userId, username, login, hashedPassword, saltString, new HashSet<>(List.of(role)));
            usersByUsername.put(username, user);
            usersByLogin.put(login, user);
            logger.info(String.format("Создан новый пользователь: %s", user));
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static void insertIntoUsers(String username, String login, String password, String salt, Connection connection) throws SQLException {
        logger.debug("insertIntoUsers - получение preparedStatement по запросу: " + SQL_INSERT_INTO_USERS);
        try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_INSERT_INTO_USERS)) {
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

    private static int getUserIdByLoginFromDB(String login, Connection connection) throws SQLException {
        logger.debug("getUserIdByLogin - получение preparedStatement по запросу: " + SQL_SELECT_USER_ID_FROM_USERS_BY_LOGIN);
        try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_SELECT_USER_ID_FROM_USERS_BY_LOGIN)) {
            preparedStatement.setString(1, login);
            logger.debug("getUserIdByLogin - выполнение preparedStatement: " + preparedStatement);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }

    public static void addRole(String username, String roleName) {
        User user = getUserByUsername(username);
        UserRole role = UserRole.valueOf(roleName);
        try (Connection connection = DataSource.getConnection()) {
            insertIntoUserToRole(user.getId(), RolesDao.getRoleId(role), connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.addRole(role);
    }

    private static void insertIntoUserToRole(int userId, int roleId, Connection connection) throws SQLException {
        logger.debug("insertIntoUserToRole - получение preparedStatement по запросу: " + SQL_INSERT_INTO_USER_TO_ROLE);
        try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_INSERT_INTO_USER_TO_ROLE)) {
            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, roleId);
            logger.debug("insertIntoUserToRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    public static void removeRole(String username, String roleName) {
        User user = getUserByUsername(username);
        UserRole role = UserRole.valueOf(roleName);
        try (Connection connection = DataSource.getConnection()) {
            deleteFromUserToRole(user.getId(), RolesDao.getRoleId(role), connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.removeRole(role);
    }

    private static void deleteFromUserToRole(int userId, int roleId, Connection connection) throws SQLException {
        logger.debug("deleteFromUserToRole - получение preparedStatement по запросу: " + SQL_DELETE_FROM_USER_TO_ROLE);
        try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_DELETE_FROM_USER_TO_ROLE)) {
            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, roleId);
            logger.debug("deleteFromUserToRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        }
    }

    public static void changeUsername(String currentUsername, String newUsername) {
        User currentUser = getUserByUsername(currentUsername);
        changeUsernameInDB(currentUser.getId(), newUsername);
        currentUser.setUsername(newUsername);
    }

    private static void changeUsernameInDB(int userId, String newUsername) {
        try (Connection connection = DataSource.getConnection()) {
            logger.debug("changeUsernameInDB - получение результата запроса: " + SQL_UPDATE_USERS_SET_USERNAME);
            try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_UPDATE_USERS_SET_USERNAME)) {
                preparedStatement.setString(1, newUsername);
                preparedStatement.setInt(2, userId);
                logger.debug("changeUsernameInDB - выполнение preparedStatement: " + preparedStatement);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static void getAllUsersData() {
        logger.debug("getAllUsersData - получение результата запроса: " + SQL_SELECT_ALL_USERS_DATA);
        try (Connection connection = DataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                try (ResultSet resultSet = statement.executeQuery(SQL_SELECT_ALL_USERS_DATA)) {
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
                            User user = new User(userId, userName, login, password, salt, banTime, new HashSet<>());
                            idToUsersData.put(userId, user);
                            usersByUsername.put(userName, user);
                            usersByLogin.put(login, user);
                            logger.debug("getAllUsersData - создался пользователь: " + user);
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
                    // Заполним роли
                    for (int userId : idToUsersData.keySet()) {
                        User user = idToUsersData.get(userId);
                        user.setRoles(idToRole.getOrDefault(userId, new HashSet<>()));
                        logger.debug("getAllUsersData - заполнились роли: " + user);
                    }
                } catch (SQLException e) {
                    logger.error(e.getMessage());
                    throw new RuntimeException(e);
                }
            } catch (SQLException e) {
                logger.error(e.getMessage());
                throw new RuntimeException(e);
            }
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static void banUser(String username, OffsetDateTime banTime) {
        User user = getUserByUsername(username);
        try (Connection connection = DataSource.getConnection()) {
            updateUserBanTime(user.getId(), banTime, connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.setBanTime(banTime);
    }

    private static void updateUserBanTime(int userId, OffsetDateTime banTime, Connection connection) throws SQLException {
        logger.debug("updateUserBanTime - получение preparedStatement по запросу: " + SQL_UPDATE_USERS_SET_BAN_TIME);
        try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_UPDATE_USERS_SET_BAN_TIME)) {
            preparedStatement.setObject(1, banTime);
            preparedStatement.setInt(2, userId);
            logger.debug("updateUserBanTime - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        }
    }

    private static User getUserByUsername(String username) {
        User user = usersByUsername.get(username);
        if (user == null) {
            logger.error(String.format("Не найден пользователь по имени: %s", username));
            throw new RuntimeException(String.format("Не найден пользователь по имени: %s", username));
        }
        return user;
    }

    public static boolean isLoginAlreadyExists(String login) {
        return usersByLogin.get(login) != null;
    }

    public static boolean isUserAdmin(String username) {
        return getUserByUsername(username).getRoles().contains(UserRole.ADMIN);
    }

    public static boolean isUserHasRole(String username, String roleName) {
        return getUserByUsername(username).getRoles().contains(UserRole.valueOf(roleName));
    }

    public static boolean isUserLastAdmin(String username) {
        for (Map.Entry<String, User> entry : usersByUsername.entrySet()) {
            if (entry.getKey().equals(username)) {
                continue;
            }
            if (entry.getValue().getRoles().contains(UserRole.ADMIN)) {
                return false;
            }
        }
        return true;
    }

    public static boolean isUserHasOneRole(String username) {
        return getUserByUsername(username).getRoles().size() == 1;
    }

    public static boolean isUsernameExists(String username) {
        return usersByUsername.get(username) != null;
    }

    public static OffsetDateTime getUserBanTime(String username) {
        return getUserByUsername(username).getBanTime();
    }

    public static String getUserInfo(String username) {
        return getUserByUsername(username).toString();
    }

    public static String getUsernameByLoginAndPassword(String login, String password) {
        User user = usersByLogin.get(login);
        if (user == null) {
            return null;
        }
        byte[] salt = decodeToByteArray(user.getSalt());
        String hashedPassword = getHashString(password, salt);
        if (user.getPassword().equals(hashedPassword)) {
            return user.getUsername();
        }
        return null;
    }

    private static byte[] getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static void createDefaultAdmin() {
        createNewUser("admin", "admin", getDefaultPasswordForAdmin(), UserRole.ADMIN);
    }

    private static String getDefaultPasswordForAdmin() {
        // Нужна только для создания первого пользователя admin/admin
        // Чтобы пользователь потом мог войти, так как с клиента летит хешированный (этой же солью) пароль
        byte[] fixedSalt = "My unique fixed salt".getBytes();
        byte[] hash = getHash("admin", fixedSalt);
        return encodeToString(hash);
    }

    private static byte[] getHash(String password, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static String getHashString(String password, byte[] salt) {
        byte[] hash = getHash(password, salt);
        return encodeToString(hash);
    }

    private static String encodeToString(byte[] data) {
        return Base64.getEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] decodeToByteArray(String data) {
        return Base64.getDecoder().decode(data);
    }
}
