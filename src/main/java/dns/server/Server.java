package dns.server;

import dns.constant.Constants;

import java.io.IOException;

/**
 * @ClassName Server
 * @Description TODO
 * @Author 梦龙
 * @Date 2022/2/14 17:16
 * @Version 1.0
 **/
public class Server {
    public Server(String rabbitMqHost, int rabbitMqPort, String rabbitMqQueueName) {
        new Thread(new UDPServer(Constants.PORT)).start();
        new Thread(new TCPServer(Constants.PORT, Constants.BACKLOG)).start();
        new Thread(new SyncServer(rabbitMqHost, rabbitMqPort, rabbitMqQueueName)).start();
    }
}
