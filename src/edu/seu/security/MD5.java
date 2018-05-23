package edu.seu.security;

import java.nio.ByteOrder;

/**
 * MD5 hash算法
 * MD5 uses big-endian convention at bit level, then little-endian convention at byte level
 * @author Pan Guixin
 * @date 2018-05-22
 */
public class MD5 {
    // magic initialization constants
    private static final int INIT_A = 0x67452310;
    private static final int INIT_B = 0xefcdab89;
    private static final int INIT_C = 0x98badcfe;
    private static final int INIT_D = 0x10325476;

    // constants for compress
    private static final int S11 = 7;
    private static final int S12 = 12;
    private static final int S13 = 17;
    private static final int S14 = 22;
    private static final int S21 = 5;
    private static final int S22 = 9;
    private static final int S23 = 14;
    private static final int S24 = 20;
    private static final int S31 = 4;
    private static final int S32 = 11;
    private static final int S33 = 16;
    private static final int S34 = 23;
    private static final int S41 = 6;
    private static final int S42 = 10;
    private static final int S43 = 15;
    private static final int S44 = 21;

    // md5一次处理字节长度
    private static final int BLOCK_SIZE = 64;

    // 计算使用的四个寄存器值
    private int state[] = new int[4];
    // 已处理的字节数
    private long bytesProcessed;
    // 字节缓存器
    private byte[] buffer = new byte[BLOCK_SIZE];
    // 字节缓存器已用字节偏移量，即已用字节数
    private int bufferOffset;
    // 临时缓存
    private int[] x = new int[16];

    private void reset() {
        state[0] = INIT_A;
        state[1] = INIT_B;
        state[2] = INIT_C;
        state[3] = INIT_D;
        bytesProcessed = 0;
    }

    /**
     * 辅助函数F, 4-byte word由int表示
     * @param x
     * @param y
     * @param z
     * @return
     */
    private static int F(int x, int y, int z) {
        return (x & y) | ((~x) & z);
    }

    private static int G(int x, int y, int z) {
        return (x & z) | (y & (~z));
    }

    private static int H(int x, int y, int z) {
        return x ^ y ^ z;
    }

    private static int I(int x, int y, int z) {
        return y ^ ( x | (~z));
    }

    /**
     * 循环左移
     * @param x 4-byte word
     * @param n 左移位数
     * @return
     */
    private static int rotateLeft(int x, int n) {
        return ((x << n) | (x >>> (32 - n)));
    }

    private static int FF(int a, int b, int c, int d, int x, int s, int ac) {
        a += F(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    private static int GG(int a, int b, int c, int d, int x, int s, int ac) {
        a += G(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    private static int HH(int a, int b, int c, int d, int x, int s, int ac) {
        a += H(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    private static int II(int a, int b, int c, int d, int x, int s, int ac) {
        a += I(b, c, d) + x + ac;
        a = rotateLeft(a, s);
        return a + b;
    }

    public byte[] getDigest() {
        long bitsProcessed = bytesProcessed << 3;

        int index = (int) bytesProcessed & 0x3f;
        int pedLen = (index < 56) ? (56 - index) : (120 - index);
    }

    public void update(byte[] input, int offset, int length) {
        if (length == 0) {
            return;
        }
        if (length < 0 || offset < 0 || ((input.length - length) < offset)) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (bytesProcessed < 0) {
            reset();
        }
        bytesProcessed += length;
        if (bufferOffset != 0) {
            int n = Math.min(length, buffer.length - bufferOffset);
            System.arraycopy(input, offset, buffer, bufferOffset, n);
            offset += n;
            bufferOffset += n;
            length -= n;
            if (bufferOffset >= BLOCK_SIZE) {
                compress(buffer, 0);
                bufferOffset = 0;
            }
        }
        if (length > BLOCK_SIZE) {
            int i;
            for (i = 0; i < (length / BLOCK_SIZE); i++) {
                compress(input, offset + i * BLOCK_SIZE);
            }
            int remainderLen = length - (i - 1) * BLOCK_SIZE;
            System.arraycopy(input, offset + (i - 1) * BLOCK_SIZE, buffer, 0, remainderLen);
            bufferOffset = remainderLen;
        }
        if (length > 0) {
            System.arraycopy(input, offset, buffer, 0, length);
            bufferOffset = length;
        }
    }

    private void compress(byte[] input, int offset) {
        b2iLittle(input, x, offset);

        int a = state[0];
        int b = state[1];
        int c = state[2];
        int d = state[3];

        /* Round 1 */
        a = FF ( a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
        d = FF ( d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
        c = FF ( c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
        b = FF ( b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
        a = FF ( a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
        d = FF ( d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
        c = FF ( c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
        b = FF ( b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
        a = FF ( a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
        d = FF ( d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
        c = FF ( c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
        b = FF ( b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
        a = FF ( a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
        d = FF ( d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
        c = FF ( c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
        b = FF ( b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

        /* Round 2 */
        a = GG ( a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
        d = GG ( d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
        c = GG ( c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
        b = GG ( b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
        a = GG ( a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
        d = GG ( d, a, b, c, x[10], S22,  0x2441453); /* 22 */
        c = GG ( c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
        b = GG ( b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
        a = GG ( a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
        d = GG ( d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
        c = GG ( c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
        b = GG ( b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
        a = GG ( a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
        d = GG ( d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
        c = GG ( c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
        b = GG ( b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

        /* Round 3 */
        a = HH ( a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
        d = HH ( d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
        c = HH ( c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
        b = HH ( b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
        a = HH ( a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
        d = HH ( d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
        c = HH ( c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
        b = HH ( b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
        a = HH ( a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
        d = HH ( d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
        c = HH ( c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
        b = HH ( b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
        a = HH ( a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
        d = HH ( d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
        c = HH ( c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
        b = HH ( b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

        /* Round 4 */
        a = II ( a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
        d = II ( d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
        c = II ( c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
        b = II ( b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
        a = II ( a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
        d = II ( d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
        c = II ( c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
        b = II ( b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
        a = II ( a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
        d = II ( d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
        c = II ( c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
        b = II ( b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
        a = II ( a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
        d = II ( d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
        c = II ( c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
        b = II ( b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    /**
     * 将long类型转换为小端序的8-byte数组
     * @param input
     * @param output
     */
    private static void l2bLittle(long input, byte[] output) {
        int[] count = new int[2];
        count[0] = (int) input;
        count[1] = (int) input >>> 32;
        for (int i = 0, j = 0; j < 8; i++, j += 4) {
            output[j] = (byte) (count[i] & 0xff);
            output[j + 1] = (byte) ((count[i] >>> 8) & 0xff);
            output[j + 2] = (byte) ((count[i] >>> 16) & 0xff);
            output[j + 3] = (byte) ((count[i] >>> 24) & 0xff);
        }
    }

    /**
     * 将offset之后（含offset）的64-byte转为16个4-byte长的word（即int）,小端序
     * @param input
     * @param output
     * @param offset
     */
    private static void b2iLittle(byte[] input, int[] output, int offset) {
        for (int i = 0, j = offset; j < offset + 64; i++, j += 4) {
            output[i] = ((input[j] & 0xff)) | ((input[j + 1] & 0xff) << 8) |
                    ((input[j + 2] & 0xff) << 16) | ((input[j + 3] & 0xff) << 24);
        }
    }

    public static void main(String[] args) {
        ByteOrder byteOrder = ByteOrder.nativeOrder();
        System.out.println(byteOrder);
    }
}

