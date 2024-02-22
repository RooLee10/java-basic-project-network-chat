package ru.li.chat.server;

public enum UserRole {
    USER, ADMIN;

    public static boolean roleNotExist(String roleName) {
        for (UserRole role : values()) {
            if (role.toString().equals(roleName)) {
                return false;
            }
        }
        return true;
    }
}

