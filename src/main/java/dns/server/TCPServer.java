package dns.server;

import dns.handler.TCPServerHandler;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

/**
 * @ClassName TCPServer
 * @Description TODO
 * @Author 梦龙
 * @Date 2022/2/14 17:26
 * @Version 1.0
 **/
public class TCPServer implements Runnable {
    private final int port;
    private final int backlog;
    public TCPServer(int port, int backlog) {
        this.port = port;
        this.backlog = backlog;
    }
    @Override
    public void run() {
        EventLoopGroup boosGroup = new NioEventLoopGroup();
        try {
            EventLoopGroup workGroup = new NioEventLoopGroup();
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(boosGroup,workGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.SO_BACKLOG,backlog)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel socketChannel) {
                            socketChannel.pipeline().addLast(new TCPServerHandler());
                        }
                    });
            bootstrap.bind(port).await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
