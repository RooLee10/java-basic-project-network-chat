package ru.li.chat.server.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.database.DataSource;

import java.sql.PreparedStatement;
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

    public static PreparedStatement getPreparedStatementCreateNewRole() {
        return preparedStatementCreateNewRole;
    }

    public static PreparedStatement getPreparedStatementGetRoleIdByRoleName() {
        return preparedStatementGetRoleIdByRoleName;
    }
}
