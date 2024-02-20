package ru.li.chat.server.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.database.DataSource;

import java.sql.PreparedStatement;
import java.sql.SQLException;

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
