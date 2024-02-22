package ru.li.chat.server;

import java.time.OffsetDateTime;
import java.util.Set;

public class User {
    private String username;
    private final String login;
    private final String password;
    private final String salt;
    private OffsetDateTime banTime;
    private Set<UserRole> roles;

    public String getUsername() {
        return username;
    }

    public void setUsername(String newUsername) {
        this.username = newUsername;
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    public String getSalt() {
        return salt;
    }

    public OffsetDateTime getBanTime() {
        return banTime;
    }

    public void setBanTime(OffsetDateTime banTime) {
        this.banTime = banTime;
    }

    public Set<UserRole> getRoles() {
        return roles;
    }

    public User(String username, String login, String password, String salt, Set<UserRole> roles) {
        this.username = username;
        this.login = login;
        this.password = password;
        this.salt = salt;
        this.roles = roles;
    }

    public void setRoles(Set<UserRole> roles) {
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

    public void addRole(UserRole role) {
        roles.add(role);
    }

    public void removeRole(UserRole role) {
        roles.remove(role);
    }

    @Override
    public String toString() {
        return String.format("User{ username='%s', login='%s', banTime='%s', roles='%s' }", username, login, banTime, roles);
    }
}
