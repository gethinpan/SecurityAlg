package edu.seu.security;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static java.lang.System.*;

public class Test {
    public static void main(String[] args) {
        KeyPairGenerator
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
