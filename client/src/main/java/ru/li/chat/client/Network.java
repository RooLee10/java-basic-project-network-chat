package ru.li.chat.client;

import com.fatboyindustrial.gsonjavatime.Converters;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.net.Socket;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

public class Network implements AutoCloseable {

    static private class Message {
        private OffsetDateTime date;
        private String text;
        private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        @Override
        public String toString() {
            return String.format("[%s] %s", OffsetDateTime.parse(date.toString()).withOffsetSameInstant(OffsetDateTime.now().getOffset()).format(formatter), text);
        }
    }

    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private Callback onMessageReceived;
    private boolean connected;
    private Gson gson;

    public void setOnMessageReceived(Callback onMessageReceived) {
        this.onMessageReceived = onMessageReceived;
    }

    public Callback getOnMessageReceived() {
        return onMessageReceived;
    }

    public boolean isConnected() {
        return connected;
    }

    public void connect(int port) throws IOException {
        socket = new Socket("localhost", port);
        this.connected = true;
        this.gson = Converters.registerOffsetDateTime(new GsonBuilder()).create();
        System.out.println("Подключились к серверу");
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        new Thread(() -> {
            try {
                while (true) {
                    String text = in.readUTF();
                    Message message = gson.fromJson(text, Message.class);
                    if (message.text.equals("/disconnect")) {
                        onMessageReceived.callback("Отключились от сервера");
                        this.connected = false;
                        break;
                    }
                    if (message.text.equals("/exit")) {
                        onMessageReceived.callback("Вы покинули чат");
                        this.connected = false;
                        break;
                    }
                    onMessageReceived.callback(message.toString());
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).start();
    }

    public void send(String message) throws IOException {
        out.writeUTF(message);
    }

    @Override
    public void close() {
        try {
            if (out != null) {
                out.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            if (in != null) {
                in.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
