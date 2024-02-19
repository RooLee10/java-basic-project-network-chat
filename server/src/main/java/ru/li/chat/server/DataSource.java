package ru.li.chat.server;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

public class DataSource {

    private final Logger logger = LogManager.getLogger(DataSource.class.getName());
    private final static HikariConfig config = new HikariConfig("server/src/main/resources/datasource.properties");
    private final HikariDataSource ds;
    private final Statement statement;
    private final PreparedStatement preparedStatementInsertIntoUsers;
    private final PreparedStatement preparedStatementInsertIntoUserToRole;
    private final PreparedStatement preparedStatementDeleteFromUserToRole;
    private final PreparedStatement preparedStatementUpdateUserBanTime;
    private final PreparedStatement preparedStatementSetNewUsernameByUserId;

    public PreparedStatement getPreparedStatementSetNewUsernameByUserId() {
        return preparedStatementSetNewUsernameByUserId;
    }

    public PreparedStatement getPreparedStatementUpdateUserBanTime() {
        return preparedStatementUpdateUserBanTime;
    }


    public PreparedStatement getPreparedStatementDeleteFromUserToRole() {
        return preparedStatementDeleteFromUserToRole;
    }

    public PreparedStatement getPreparedStatementCreateNewRole() {
        return preparedStatementCreateNewRole;
    }

    private final PreparedStatement preparedStatementCreateNewRole;

    public PreparedStatement getPreparedStatementGetRoleIdByRoleName() {
        return preparedStatementGetRoleIdByRoleName;
    }

    private final PreparedStatement preparedStatementGetRoleIdByRoleName;

    public PreparedStatement getPreparedStatementGetUserIdByLogin() {
        return preparedStatementGetUserIdByLogin;
    }

    private final PreparedStatement preparedStatementGetUserIdByLogin;

    public PreparedStatement getPreparedStatementInsertIntoUserToRole() {
        return preparedStatementInsertIntoUserToRole;
    }

    public PreparedStatement getPreparedStatementInsertIntoUsers() {
        return preparedStatementInsertIntoUsers;
    }

    public Statement getStatement() {
        return statement;
    }

    public DataSource() throws SQLException {
        logger.info("Создался DataSource - pool connections");
        this.ds = new HikariDataSource(config);
        this.statement = getConnection().createStatement();
        this.preparedStatementInsertIntoUsers = getConnection().prepareStatement("INSERT INTO Users (user_name, login, password, salt) values (?, ?, ?, ?)");
        this.preparedStatementInsertIntoUserToRole = getConnection().prepareStatement("INSERT INTO UserToRole (user_id, role_id) values (?, ?)");
        this.preparedStatementGetUserIdByLogin = getConnection().prepareStatement("SELECT u.user_id FROM Users u WHERE u.login = ?");
        this.preparedStatementGetRoleIdByRoleName = getConnection().prepareStatement("SELECT r.role_id FROM Roles r WHERE r.role_name = ?");
        this.preparedStatementCreateNewRole = getConnection().prepareStatement("INSERT INTO Roles (role_name) values (?)");
        this.preparedStatementDeleteFromUserToRole = getConnection().prepareStatement("DELETE FROM UserToRole WHERE user_id = ? and role_id = ?");
        this.preparedStatementUpdateUserBanTime = getConnection().prepareStatement("UPDATE Users SET ban_time = ? WHERE user_id = ?");
        this.preparedStatementSetNewUsernameByUserId = getConnection().prepareStatement("Method...");
    }

    //    private static final String DATABASE_URL = "jdbc:postgresql://localhost:5432/UserService";
//    private static final String LOGIN = "postgres";
//    private static final String PASSWORD = "123456";

    public Connection getConnection() throws SQLException {
        return ds.getConnection();
    }
}
