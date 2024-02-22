package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.SQLException;

public class ServerApplication {
    private static final Logger LOGGER = LogManager.getLogger(ServerApplication.class.getName());
    public static void main(String[] args) throws SQLException {
        LOGGER.info("Запуск приложения");
        Server server = new Server(Integer.parseInt(String.valueOf(System.getProperties().getOrDefault("port", 8089))));
        server.start();
    }
}
