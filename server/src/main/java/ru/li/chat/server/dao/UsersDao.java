package ru.li.chat.server.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.User;
import ru.li.chat.server.UserRole;
import ru.li.chat.server.database.DataSource;

import java.sql.*;
import java.time.OffsetDateTime;
import java.util.*;

public class UsersDao {
    private static Logger logger = LogManager.getLogger(UsersDao.class.getName());
    private static final String SQL_UPDATE_USERS_SET_BAN_TIME = "UPDATE Users SET ban_time = ? WHERE user_id = ?";
    private static final String SQL_UPDATE_USERS_SET_USERNAME = "UPDATE Users SET user_name = ? WHERE user_id = ?";
    public static final String SQL_SELECT_USER_ID_FROM_USERS = "SELECT u.user_id FROM Users u WHERE u.login = ?";
    private static final String SQL_DELETE_FROM_USER_TO_ROLE = "DELETE FROM UserToRole WHERE user_id = ? and role_id = ?";
    public static final String SQL_SELECT_ALL_USERS_DATA = "SELECT u.user_id, u.user_name, u.login, u.password, u.salt, u.ban_time, r.role_name FROM UserToRole utr JOIN Users u ON utr.user_id = u.user_id JOIN Roles r ON utr.role_id = r.role_id";
    public static final String SQL_INSERT_INTO_USERS = "INSERT INTO Users (user_name, login, password, salt) values (?, ?, ?, ?)";
    public static final String SQL_INSERT_INTO_USER_TO_ROLE = "INSERT INTO UserToRole (user_id, role_id) values (?, ?)";
    private static PreparedStatement preparedStatementUpdateUserBanTime;
    private static PreparedStatement preparedStatementSetNewUsernameByUserId;
    private static PreparedStatement preparedStatementGetUserIdByLogin;
    private static PreparedStatement preparedStatementDeleteFromUserToRole;
    private static PreparedStatement preparedStatementInsertIntoUserToRole;

    static {
        try {
            preparedStatementUpdateUserBanTime = DataSource.getConnection().prepareStatement(SQL_UPDATE_USERS_SET_BAN_TIME);
            preparedStatementSetNewUsernameByUserId = DataSource.getConnection().prepareStatement(SQL_UPDATE_USERS_SET_USERNAME);
            preparedStatementGetUserIdByLogin = DataSource.getConnection().prepareStatement(SQL_SELECT_USER_ID_FROM_USERS);
            preparedStatementDeleteFromUserToRole = DataSource.getConnection().prepareStatement(SQL_DELETE_FROM_USER_TO_ROLE);
            preparedStatementInsertIntoUserToRole = DataSource.getConnection().prepareStatement(SQL_INSERT_INTO_USER_TO_ROLE);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static User createNewUser(String username, String login, String hashedPassword, String saltString, UserRole role) {
        try (Connection connection = DataSource.getConnection()) {
            logger.debug(String.format("createNewUser %s", connection));
            connection.setAutoCommit(false);
            insertIntoUsers(username, login, hashedPassword, saltString, connection);
            int userId = getUserIdByLogin(login, connection);
            int roleId = RolesDao.getRoleIdByRoleName(role.toString(), connection);
            insertIntoUserToRole(userId, roleId, connection);
            connection.setAutoCommit(true);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        return new User(username, login, hashedPassword, saltString, new HashSet<>(List.of(role)));
    }

    public static int getUserIdByLogin(String login) throws SQLException {
        PreparedStatement preparedStatement = UsersDao.getPreparedStatementGetUserIdByLogin();
        preparedStatement.setString(1, login);
        logger.debug("getUserIdByLogin - выполнение preparedStatement: " + preparedStatement);
        try (ResultSet resultSet = preparedStatement.executeQuery()) {
            resultSet.next();
            return resultSet.getInt(1);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    public static int getUserIdByLogin(String login, Connection connection) throws SQLException {
        try (PreparedStatement preparedStatement = connection.prepareStatement(UsersDao.SQL_SELECT_USER_ID_FROM_USERS)) {
            preparedStatement.setString(1, login);
            logger.debug("getUserIdByLogin - выполнение preparedStatement: " + preparedStatement);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                resultSet.next();
                return resultSet.getInt(1);
            } catch (SQLException e) {
                logger.error(e.getMessage());
                throw new SQLException(e);
            }
        }
    }

    private static void insertIntoUsers(String username, String login, String password, String salt, Connection connection) throws SQLException {
        logger.debug("insertIntoUsers - получение preparedStatement по запросу: " + UsersDao.SQL_INSERT_INTO_USERS);
        try (PreparedStatement preparedStatement = connection.prepareStatement(UsersDao.SQL_INSERT_INTO_USERS)) {
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

    public static void insertIntoUserToRole(String login, String roleName) throws SQLException {
        int userId = getUserIdByLogin(login);
        int roleId = RolesDao.getRoleIdByRoleName(roleName);
        PreparedStatement preparedStatement = UsersDao.getPreparedStatementInsertIntoUserToRole();
        preparedStatement.setInt(1, userId);
        preparedStatement.setInt(2, roleId);
        logger.debug("insertIntoUserToRole - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    public static void insertIntoUserToRole(int userId, int roleId, Connection connection) throws SQLException {
        logger.debug("insertIntoUserToRole - получение preparedStatement по запросу: " + UsersDao.SQL_INSERT_INTO_USER_TO_ROLE);
        try (PreparedStatement preparedStatement = connection.prepareStatement(UsersDao.SQL_INSERT_INTO_USER_TO_ROLE)) {
            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, roleId);
            logger.debug("insertIntoUserToRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    public static void deleteFromUserToRole(String login, String roleName) throws SQLException {
        int userId = UsersDao.getUserIdByLogin(login);
        int roleId = RolesDao.getRoleIdByRoleName(roleName);
        PreparedStatement preparedStatement = UsersDao.getPreparedStatementDeleteFromUserToRole();
        preparedStatement.setInt(1, userId);
        preparedStatement.setInt(2, roleId);
        logger.debug("deleteFromUserToRole - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    public static void updateUserBanTime(int userId, OffsetDateTime banTime) throws SQLException {
        PreparedStatement preparedStatement = UsersDao.getPreparedStatementUpdateUserBanTime();
        preparedStatement.setObject(1, banTime);
        preparedStatement.setInt(2, userId);
        logger.debug("updateUserBanTime - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    public static void changeUsernameInDataBase(String login, String newUsername) {
        try {
            int userId = getUserIdByLogin(login);
            setNewUsernameByUserId(userId, newUsername);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static void setNewUsernameByUserId(int userId, String newUsername) throws SQLException {
        PreparedStatement preparedStatement = UsersDao.getPreparedStatementSetNewUsernameByUserId();
        preparedStatement.setString(1, newUsername);
        preparedStatement.setInt(2, userId);
        logger.debug("setNewUsernameByUserId - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    public static List<User> getAllUsersData() {
        List<User> users = new ArrayList<>();
        logger.debug("fillUsers - получение результата запроса: " + UsersDao.SQL_SELECT_ALL_USERS_DATA);
        try (Connection connection = DataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                try (ResultSet resultSet = statement.executeQuery(UsersDao.SQL_SELECT_ALL_USERS_DATA)) {
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
                    // Заполним роли
                    for (int userId : idToUsersData.keySet()) {
                        User user = idToUsersData.get(userId);
                        user.setRoles(idToRole.getOrDefault(userId, new HashSet<>()));
                        users.add(user);
                        logger.debug("fillUsers - заполнились роли: " + user);
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
        return users;
    }

    public static PreparedStatement getPreparedStatementUpdateUserBanTime() {
        return preparedStatementUpdateUserBanTime;
    }

    public static PreparedStatement getPreparedStatementSetNewUsernameByUserId() {
        return preparedStatementSetNewUsernameByUserId;
    }

    public static PreparedStatement getPreparedStatementGetUserIdByLogin() {
        return preparedStatementGetUserIdByLogin;
    }

    public static PreparedStatement getPreparedStatementDeleteFromUserToRole() {
        return preparedStatementDeleteFromUserToRole;
    }

    public static PreparedStatement getPreparedStatementInsertIntoUserToRole() {
        return preparedStatementInsertIntoUserToRole;
    }
}
