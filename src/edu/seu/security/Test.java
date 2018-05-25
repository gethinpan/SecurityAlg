package edu.seu.security;

import java.math.BigInteger;

import static java.lang.System.*;

public class Test {
    public static void main(String[] args) {
//        BigInteger l = new BigInteger(Long.toString(Long.MAX_VALUE));
//        out.println(l);
//        l = l.add(BigInteger.ONE);
//        out.println(l);
//        l = l.shiftLeft(3);
//        out.println(l);
        byte[] out = new byte[8];
        long[] in = {Long.MAX_VALUE};
        l2bBig(in, 0, out, 0, 8);
        printByteArray(out);
        out[0] = (byte) 0xff;
        b2lBig(out, 0, in, 0, 1);
        System.out.println(in[0] ^ -1L);
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
