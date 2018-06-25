package edu.seu.security;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static java.lang.System.*;

public class Test {
    public static void main(String[] args) throws Exception {
        RSAKey key = new RSAKey(2048);
        RSAKey.KeyPair keyPair = key.generateKeyPair();
        String rawMsg = "我是万王之王" +
                "功业盖物,强者折服”" +
                "此外，荡然无物" +
                "废墟四周，唯余黄沙莽莽" +
                "寂寞荒凉，伸展四方。" +
                "我是万王之王" +
                "功业盖物,强者折服”" +
                "此外，荡然无物" +
                "废墟四周，唯余黄沙莽莽" +
                "寂寞荒凉，伸展四方。" +
                "我是万王之王" +
                "功业盖物,强者折服”" +
                "此外，荡然无物" +
                "废墟四周，唯余黄沙莽莽" +
                "寂寞荒凉，伸展四方。";
        byte[] msg = rawMsg.getBytes("UTF-8");
        printByteArray(msg);
        RSA rsa = new RSA(3, keyPair.getPrivateKey());
        byte[] encrypted = rsa.process(msg);
        printByteArray(encrypted);
        RSA drsa = new RSA(4, keyPair.getPublicKey());
        byte[] decrypted = drsa.process(encrypted);
        printByteArray(decrypted);
    }

    private static void printByteArray(byte[] array) {
        for (int i = 0; i < array.length; i++) {
            System.out.print("0x" + Integer.toHexString(array[i] & 0xFF) + " ");
        }
        System.out.println();
    }

    private static void l2bBig(long[] in, int inOfs, byte[] out, int outOfs, int len) {
        len += outOfs;
        while (outOfs < len) {
            long i = in[inOfs++];
            out[outOfs++] = (byte) (i >>> 56);
            out[outOfs++] = (byte) (i >>> 48);
            out[outOfs++] = (byte) (i >>> 40);
            out[outOfs++] = (byte) (i >>> 32);
            out[outOfs++] = (byte) (i >>> 24);
            out[outOfs++] = (byte) (i >>> 16);
            out[outOfs++] = (byte) (i >>> 8);
            out[outOfs++] = (byte) i;
        }
    }

    private static void b2lBig(byte[] in, int inOfs, long[] out, int outOfs, int len) {
        len += outOfs;
        while (outOfs < len) {
            out[outOfs++] = ((in[inOfs++] & 0xffL) << 56) | ((in[inOfs++] & 0xffL) << 48) |
                    ((in[inOfs++] & 0xffL) << 40) | ((in[inOfs++] & 0xffL) << 32) | ((in[inOfs++] & 0xffL) << 24) |
                    ((in[inOfs++] & 0xffL) << 16) | ((in[inOfs++] & 0xffL) << 8) | (in[inOfs] & 0xffL);
        }
    }
}
