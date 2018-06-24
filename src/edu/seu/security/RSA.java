package edu.seu.security;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * RSA加解密算法，采用PKCS#1 v1.5中的encryption-block formatting 方法
 *
 * @author Pan Guixin
 * @date 2018-06-23
 */
public class RSA {
    /**
     * 定义操作模式常数
     */
    private final int ENCRYPT = 1;
    private final int DECRYPT = 2;
    private final int SIGN = 3;
    private final int VERIFY = 4;

    private int mode;
    private RSAKey.PublicKey publicKey;
    private RSAKey.PrivateKey privateKey;
    private int blockSize;
    private byte[] buffer;
    private int bufferOfs;

    /**
     * mode只能为1或4
     *
     * @param mode
     * @param publicKey
     */
    public RSA(int mode, RSAKey.PublicKey publicKey) {
        this.mode = mode;
        this.publicKey = publicKey;
        this.blockSize = getByteLength(publicKey.getModule());
        if (mode == 1) {
            this.buffer = new byte[blockSize - 11];
        } else {
            this.buffer = new byte[blockSize];
        }
        this.bufferOfs = 0;
    }

    /**
     * mode只能为2或3
     *
     * @param mode
     * @param privateKey
     */
    public RSA(int mode, RSAKey.PrivateKey privateKey) {
        this.mode = mode;
        this.privateKey = privateKey;
        this.blockSize = getByteLength(privateKey.getModule());
        if (mode == 3) {
            this.buffer = new byte[blockSize - 11];
        } else {
            this.buffer = new byte[blockSize];
        }
        this.bufferOfs = 0;
    }

    /**
     * PKCS#1 v2.1 中定义的RSAEP模式
     * @param msg
     * @return
     */
    private byte[] encrypt(byte[] msg) {
        BigInteger m = new BigInteger(msg);
        return m.modPow(publicKey.getPublicExponent(), publicKey.getModule()).toByteArray();
    }

    /**
     * RSADP模式
     * @param msg
     * @return
     */
    private byte[] decrypt(byte[] msg) {
        BigInteger c = new BigInteger(msg);
        return c.modPow(privateKey.getPrivateExponent(), privateKey.getModule()).toByteArray();
    }

    /**
     * RSASP1模式
     * @param msg
     * @return
     */
    private byte[] sign(byte[] msg) {
        return decrypt(msg);
    }

    /**
     * RSAVP1模式
     * @param msg
     * @return
     */
    private byte[] verify(byte[] msg) {
        return encrypt(msg);
    }

    /**
     * 参考rfc2313-pkcs#1 v1.5
     * EB = 00 || BT || PS || 00 || D
     *
     * @param date
     * @return
     */
    private byte[] pad(byte[] date) {
        byte[] padded = new byte[blockSize];
        System.arraycopy(date, 0, padded, blockSize - date.length, date.length);
        int psLen = blockSize - date.length - 3;
        int index = 0;
        padded[index++] = 0x00;
        if (mode == ENCRYPT) {
            padded[index++] = 0x01;
            while (psLen-- > 0) {
                padded[index++] = (byte)0xff;
            }
        } else {
            padded[index++] = 0x02;
            SecureRandom random = new SecureRandom();
            while (psLen > 0) {
                byte[] r = new byte[psLen];
                random.nextBytes(r);
                for (int i = 0; i < r.length; i++) {
                    if (r[i] != 0) {
                        padded[index++] = r[i];
                        psLen--;
                    }
                }
            }
        }
        return padded;
    }

    /**
     * @param padded
     * @return
     */
    private byte[] unpad(byte[] padded) {
        int index = 2;
        while (padded[index] != 0) {
            index++;
        }
        index++;
        byte[] date = new byte[padded.length - index];
        System.arraycopy(padded, index, date, 0, date.length);
        return date;
    }

    private int getByteLength(BigInteger b) {
        int bitLen = b.bitLength();
        return (bitLen + 7) >> 3;
    }
}
