package dns.handler;

import dns.constant.Constants;
import dns.core.Message;
import dns.core.Type;
import dns.message.MessageQuery;
import dns.message.MessageTranslate;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;

/**
 * @ClassName UDPServerHandler
 * @Description TODO
 * @Author 梦龙
 * @Date 2021/7/12 17:54
 * @Version 1.0
 **/
@ChannelHandler.Sharable
public class UDPServerHandler extends SimpleChannelInboundHandler<DatagramPacket> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket datagramPacket) {
        Message message = MessageTranslate.decode(Constants.UDP_MESSAGE, datagramPacket.content());
        if (message != null) {
            if (message.getQuestion().getType() != Type.ANY) {
                MessageQuery.query(message, datagramPacket.sender().getHostString());
                ctx.writeAndFlush(new DatagramPacket(MessageTranslate.encode(Constants.UDP_MESSAGE, message), datagramPacket.sender()));
            }
        }
    }
}
