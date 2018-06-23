package edu.seu.security;

import java.math.BigInteger;

/**
 * RSA加解密算法
 *
 * @author Pan Guixin
 * @date 2018-06-23
 */
public class RSA {
    public static byte[] encrypt(byte[] msg, RSAKey.PublicKey publicKey) {
        BigInteger m = new BigInteger(msg);
        return m.modPow(publicKey.getPublicExponent(), publicKey.getModule()).toByteArray();
    }
}
