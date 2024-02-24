package ru.li.chat.server.database;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import ru.li.chat.server.ClientHandler;
import ru.li.chat.server.UserRole;
import ru.li.chat.server.UserService;
import ru.li.chat.server.dao.UsersDao;

import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

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
    public List<String> getRegistrationErrors(String username, String login, String password, ClientHandler clientHandler) {
        List<String> errors = new ArrayList<>();
        if (isUsernameExists(username)) {
            logger.warn(String.format("%s username уже занят: %s", clientHandler, username));
            errors.add("username уже занят");
        }
        if (isLoginAlreadyExists(login)) {
            logger.warn(String.format("%s login уже занят: %s", clientHandler, login));
            errors.add("login уже занят");
        }
        return errors;
    }

    @Override
    public List<String> getAuthenticationErrors(String login, String password, ClientHandler clientHandler) {
        List<String> errors = new ArrayList<>();
        String usernameFromUserService = getUsernameByLoginAndPassword(login, password);
        if (usernameFromUserService == null) {
            logger.warn(String.format("%s Неверно указан логин или пароль: %s|%s", clientHandler, login, password));
            errors.add("неверно указан логин или пароль");
            return errors;
        }
        OffsetDateTime userBanTime = getUserBanTime(usernameFromUserService);
        if (userBanTime == OffsetDateTime.MAX) {
            logger.warn(String.format("%s Попытка входа в заблокированную учетную запись: бан до %s", clientHandler, userBanTime));
            errors.add("учетная запись заблокирована навсегда");
        }
        if (userBanTime != null && OffsetDateTime.now().isBefore(userBanTime)) {
            logger.warn(String.format("%s Попытка входа в заблокированную учетную запись: бан до %s", clientHandler, userBanTime));
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss ZZZZ");
            formatter.withZone(ZoneId.systemDefault());
            errors.add(String.format("учетная запись заблокирована до %s", userBanTime.format(formatter)));
        }
        return errors;
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
