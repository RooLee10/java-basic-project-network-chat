package ru.li.chat.server.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.UserRole;
import ru.li.chat.server.database.DataSource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class RolesDao {
    private static Logger logger = LogManager.getLogger(RolesDao.class.getName());
    public final static String SQL_INSERT_INTO_ROLES = "INSERT INTO Roles (role_name) values (?)";
    public final static String SQL_SELECT_ROLE_ID_FROM_ROLES = "SELECT r.role_id FROM Roles r WHERE r.role_name = ?";
    private static Map<UserRole, Integer> roleId = new HashMap<>();

    static {
        for (UserRole role : UserRole.values()) {
            roleId.put(role, getRoleIdByRoleName(role.toString()));
        }
    }

    public static int getRoleId(UserRole role) {
        return roleId.get(role);
    }

    private static int getRoleIdByRoleName(String roleName) {
        try (Connection connection = DataSource.getConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_SELECT_ROLE_ID_FROM_ROLES)) {
                preparedStatement.setString(1, roleName);
                logger.debug("getRoleIdByRoleName - выполнение preparedStatement: " + preparedStatement);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    if (!resultSet.next()) {
                        createNewRole(roleName, connection);
                        return getRoleIdByRoleName(roleName);
                    }
                    return resultSet.getInt(1);
                }
            }
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private static void createNewRole(String roleName, Connection connection) throws SQLException {
        try (PreparedStatement preparedStatement = connection.prepareStatement(SQL_INSERT_INTO_ROLES)) {
            preparedStatement.setString(1, roleName);
            logger.debug("createNewRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        }
    }
}
