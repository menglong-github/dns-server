package dns.message;

import dns.constant.Constants;
import dns.core.Message;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.nio.ByteBuffer;

/**
 * @ClassName MessageTranslate
 * @Description TODO
 * @Author 梦龙
 * @Date 2022/2/14 18:55
 * @Version 1.0
 **/
public class MessageTranslate {
    public static Message decode(int messageType, ByteBuf byteBuf) {
        if (messageType == Constants.UDP_MESSAGE) {
            return decodeUDPMessage(byteBuf);
        } else {
            return decodeTCPMessage(byteBuf);
        }
    }

    private static Message decodeUDPMessage(ByteBuf byteBuf) {
        Message message = null;
        try {
            message = new Message(byteBuf.nioBuffer());
        } catch (Exception ignored) {}
        return message;
    }

    private static Message decodeTCPMessage(ByteBuf byteBuf) {
        Message message = null;
        try {
            message = new Message(byteBuf.nioBuffer(2, byteBuf.readableBytes()));
        } catch (Exception ignored) {} finally {
            byteBuf.release();
        }
        return message;
    }

    public static ByteBuf encode(int messageType, Message message) {
        if (messageType == Constants.UDP_MESSAGE) {
            return encodeUDPMessage(message);
        } else {
            return encodeTCPMessage(message);
        }
    }

    private static ByteBuf encodeUDPMessage(Message message) {
        return Unpooled.copiedBuffer(message.toWire());
    }

    private static ByteBuf encodeTCPMessage(Message message) {
        byte[] bytes = message.toWire();
        ByteBuffer buffer = ByteBuffer.allocate(bytes.length + 2);
        buffer.put((byte) (bytes.length >>> 8));
        buffer.put((byte) (bytes.length & 0xFF));
        buffer.put(bytes);
        buffer.flip();
        return Unpooled.copiedBuffer(buffer.array());
    }


}
