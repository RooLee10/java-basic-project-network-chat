package ru.li.chat.server.database;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.UserRole;
import ru.li.chat.server.UserService;
import ru.li.chat.server.dao.UsersDao;

import java.time.OffsetDateTime;

public class DataBaseUserService implements UserService {
    private final Logger logger = LogManager.getLogger(DataBaseUserService.class.getName());

    @Override
    public String getUsernameByLoginAndPassword(String login, String password) {
        return UsersDao.getUsernameByLoginAndPassword(login, password);
    }

    @Override
    public String getUserInfo(String username) {
        return UsersDao.getUserInfo(username);
    }

    @Override
    public OffsetDateTime getUserBanTime(String username) {
        return UsersDao.getUserBanTime(username);
    }

    @Override
    public boolean isUsernameExists(String username) {
        return UsersDao.isUsernameExists(username);
    }

    @Override
    public boolean isLoginAlreadyExists(String login) {
        return UsersDao.isLoginAlreadyExists(login);
    }

    @Override
    public boolean isUserAdmin(String username) {
        return UsersDao.isUserAdmin(username);
    }

    @Override
    public void createNewUser(String username, String login, String password, UserRole role) {
        UsersDao.createNewUser(username, login, password, role);
    }

    @Override
    public void addRole(String username, String roleName) {
        UsersDao.addRole(username, roleName);
    }

    @Override
    public void removeRole(String username, String roleName) {
        UsersDao.removeRole(username, roleName);
    }

    @Override
    public void changeUsername(String currentUsername, String newUsername) {
        UsersDao.changeUsername(currentUsername, newUsername);
    }

    @Override
    public void banUser(String username, OffsetDateTime banTime) {
        UsersDao.banUser(username, banTime);
    }

    @Override
    public boolean isUserHasRole(String username, String roleName) {
        return UsersDao.isUserHasRole(username, roleName);
    }

    @Override
    public boolean isUserHasOneRole(String username) {
        return UsersDao.isUserHasOneRole(username);
    }

    @Override
    public boolean isUserLastAdmin(String username) {
        return UsersDao.isUserLastAdmin(username);
    }
}
