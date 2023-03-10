package dns.handler;

import dns.constant.Constants;
import dns.core.Message;
import dns.core.Type;
import dns.message.MessageQuery;
import dns.message.MessageTranslate;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import java.net.InetSocketAddress;

/**
 * @ClassName TCPServerHandler
 * @Description TODO
 * @Author 梦龙
 * @Date 2021/7/20 15:46
 * @Version 1.0
 **/
@ChannelHandler.Sharable
public class TCPServerHandler extends ChannelInboundHandlerAdapter {

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg){
        Message message = MessageTranslate.decode(Constants.TCP_MESSAGE, (ByteBuf) msg);
        if (message != null) {
            if (message.getQuestion().getType() != Type.ANY) {
                MessageQuery.query(message, ((InetSocketAddress)ctx.channel().remoteAddress()).getHostString());
                ctx.writeAndFlush(MessageTranslate.encode(Constants.TCP_MESSAGE, message));
            }
        }
    }
}
