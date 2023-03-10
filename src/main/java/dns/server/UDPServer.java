package dns.server;

import dns.handler.UDPServerHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.epoll.EpollChannelOption;
import io.netty.channel.epoll.EpollDatagramChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;

/**
 * @ClassName UDPServer
 * @Description TODO
 * @Author 梦龙
 * @Date 2022/2/14 17:14
 * @Version 1.0
 **/
public class UDPServer implements Runnable {
    private final int port;
    public UDPServer(int port) {
        this.port = port;
    }

    @Override
    public void run() {
//        Bootstrap bootstrap = new Bootstrap();
//        bootstrap.group(new NioEventLoopGroup())
//                .channel(NioDatagramChannel.class)
//                .option(ChannelOption.SO_BROADCAST, true)
//                .handler(new UDPServerHandler());
//        try {
//            bootstrap.bind(port).sync().channel().closeFuture().await();
//        } catch (InterruptedException e) {
//            throw new RuntimeException(e);
//        }

        int theadNums = Runtime.getRuntime().availableProcessors();
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(new EpollEventLoopGroup(theadNums))
                .channel(EpollDatagramChannel.class)
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .option(EpollChannelOption.SO_REUSEPORT, true)
                .handler(new ChannelInitializer<EpollDatagramChannel>() {
                    @Override
                    protected void initChannel(EpollDatagramChannel epollDatagramChannel) {
                        epollDatagramChannel.pipeline().addLast(new UDPServerHandler());
                    }
                });
        ChannelFuture future;
        for (int index = 0; index < theadNums; index++) {
            try {
                future = bootstrap.bind(port).await();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
