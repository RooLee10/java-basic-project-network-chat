package ru.li.chat.server.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.database.DataSource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class RolesDao {
    private static Logger logger = LogManager.getLogger(RolesDao.class.getName());
    public final static String SQL_INSERT_INTO_ROLES = "INSERT INTO Roles (role_name) values (?)";
    public final static String SQL_SELECT_ROLE_ID_FROM_ROLES = "SELECT r.role_id FROM Roles r WHERE r.role_name = ?";
    private static PreparedStatement preparedStatementCreateNewRole;
    private static PreparedStatement preparedStatementGetRoleIdByRoleName;

    static {
        try {
            preparedStatementCreateNewRole = DataSource.getConnection().prepareStatement(SQL_INSERT_INTO_ROLES);
            preparedStatementGetRoleIdByRoleName = DataSource.getConnection().prepareStatement(SQL_SELECT_ROLE_ID_FROM_ROLES);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public static int getRoleIdByRoleName(String roleName) throws SQLException {
        PreparedStatement preparedStatement = RolesDao.getPreparedStatementGetRoleIdByRoleName();
        preparedStatement.setString(1, roleName);
        logger.debug("getRoleIdByRoleName - выполнение preparedStatement: " + preparedStatement);
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

    public static int getRoleIdByRoleName(String roleName, Connection connection) throws SQLException {
        try (PreparedStatement preparedStatement = connection.prepareStatement(RolesDao.SQL_SELECT_ROLE_ID_FROM_ROLES)) {
            preparedStatement.setString(1, roleName);
            logger.debug("getRoleIdByRoleName - выполнение preparedStatement: " + preparedStatement);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (!resultSet.next()) {
                    createNewRole(roleName, connection);
                    return getRoleIdByRoleName(roleName, connection);
                }
                return resultSet.getInt(1);
            } catch (SQLException e) {
                logger.error(e.getMessage());
                throw new SQLException(e);
            }
        }
    }

    public static void createNewRole(String roleName) throws SQLException {
        PreparedStatement preparedStatement = RolesDao.getPreparedStatementCreateNewRole();
        preparedStatement.setString(1, roleName);
        logger.debug("createNewRole - выполнение preparedStatement: " + preparedStatement);
        preparedStatement.executeUpdate();
    }

    public static void createNewRole(String roleName, Connection connection) throws SQLException {
        try (PreparedStatement preparedStatement = connection.prepareStatement(RolesDao.SQL_INSERT_INTO_ROLES)) {
            preparedStatement.setString(1, roleName);
            logger.debug("createNewRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    public static PreparedStatement getPreparedStatementCreateNewRole() {
        return preparedStatementCreateNewRole;
    }

    public static PreparedStatement getPreparedStatementGetRoleIdByRoleName() {
        return preparedStatementGetRoleIdByRoleName;
    }
}
