package dns;
import dns.constant.Constants;
import dns.core.*;
import dns.server.Server;

import java.io.*;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeoutException;

/**
 * Hello world!
 *
 */
public class Main
{
    public static void main( String[] args ) {
        new Server(args[0], Integer.parseInt(args[1]), args[2]);
    }
}
