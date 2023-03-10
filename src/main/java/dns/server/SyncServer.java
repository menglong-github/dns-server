package dns.server;

import com.rabbitmq.client.*;
import dns.cache.ZoneCache;
import dns.constant.Constants;
import dns.core.TransferZone;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

public class SyncServer implements Runnable {

    private String host;

    private int port;

    private String queueName;

    public SyncServer(String host, int port, String queueName) {
        this.host = host;
        this.port = port;
        this.queueName = queueName;
    }

    @Override
    public void run() {
        ConnectionFactory connectionFactory = new ConnectionFactory();
        connectionFactory.setHost(host);
        connectionFactory.setPort(port);
        connectionFactory.setVirtualHost("/");
        connectionFactory.setUsername(Constants.RABBIT_MQ_USER);
        connectionFactory.setPassword(Constants.RABBIT_MQ_PASSWORD);

        //2 通过连接工厂创建连接
        Connection connection = null;
        try {
            connection = connectionFactory.newConnection();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (TimeoutException e) {
            throw new RuntimeException(e);
        }

        //3 通过connection创建一个Channel
        Channel channel = null;
        try {
            channel = connection.createChannel();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        //4 声明（创建）一个队列
//        参数：队列名称、持久化与否、独占与否、无消息队列是否自动删除、消息参数
//        queueDeclare(String queue, boolean durable, boolean exclusive, boolean autoDelete, Map<String, Object> arguments)
        try {
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueDeclare(Constants.RABBIT_INIT_QUEUE, true, false, false, null);
            channel.queueBind(queueName, Constants.EXCHANGE_NAME, "");
            channel.basicPublish("", Constants.RABBIT_INIT_QUEUE, null, queueName.getBytes(StandardCharsets.UTF_8));
            channel.basicConsume(queueName, true, new Consumer() {
                @Override
                public void handleConsumeOk(String s) {

                }

                @Override
                public void handleCancelOk(String s) {

                }

                @Override
                public void handleCancel(String s) throws IOException {

                }

                @Override
                public void handleShutdownSignal(String s, ShutdownSignalException e) {

                }

                @Override
                public void handleRecoverOk(String s) {

                }

                @Override
                public void handleDelivery(String s, Envelope envelope, AMQP.BasicProperties basicProperties, byte[] bytes) throws IOException {
                    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
                    try {
                        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
                        TransferZone transferZone = (TransferZone) objectInputStream.readObject();
                        if (transferZone.getOperationType() == 0) {
                            ZoneCache.cache.remove(transferZone.getMaster());
                        } else {
                            ZoneCache.cache.put(transferZone.getMaster(), transferZone.getZoneMap());
                        }
                    } catch (IOException | ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                }
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
