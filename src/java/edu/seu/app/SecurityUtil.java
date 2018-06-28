package edu.seu.app;

import edu.seu.security.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 *安全函数应用类
 *
 * @author Pan Guixin
 * @date 2018-06-27
 */
public class SecurityUtil {
    private String symEncAlg;
    private String symKeySeed;
    private int blockLen;
    private String hashAlg;
    private String rsaKeySize1;
    private String rsaKeySize2;
    private byte[] symKey;
    private RSAKey.KeyPair rsaKey1;
    private RSAKey.KeyPair rsaKey2;
    final BASE64Decoder decoder = new BASE64Decoder();
    final BASE64Encoder encoder = new BASE64Encoder();
    public String senderMessage = "";

    public SecurityUtil(String symEncAlg, String symKeySeed,
                        String hashAlg, String rsaKeySize1, String rsaKeySize2) {
        this.symEncAlg = symEncAlg;
        this.symKeySeed = symKeySeed;
        this.hashAlg = hashAlg;
        this.rsaKeySize1 = rsaKeySize1;
        this.rsaKeySize2 = rsaKeySize2;
        initialize();
    }

    private byte[] generateSymKey(String symKeySeed, int len) {
        byte[] symKey = new byte[len];
        if (symKeySeed == null) {
            SecureRandom random = new SecureRandom();
            random.nextBytes(symKey);
        } else {
            SecureRandom random = new SecureRandom(symKeySeed.getBytes());
            random.nextBytes(symKey);
        }
        return symKey;
    }

    private void initialize() {
        if (symEncAlg.equals("DES")) {
            symKey = generateSymKey(symKeySeed, 8);
            blockLen = 8;
        } else {
            symKey = generateSymKey(symKeySeed, 16);
            blockLen = 16;
        }
        rsaKey1 = new RSAKey(Integer.parseInt(rsaKeySize1)).generateKeyPair();
        rsaKey2 = new RSAKey(Integer.parseInt(rsaKeySize2)).generateKeyPair();
    }

    /**
     * 获取加密参数信息
     * @param user
     * @return
     */
    public String getParameterInfo(int user) {
        StringBuilder builder = new StringBuilder();
        builder.append("对称加密算法：" + symEncAlg + "\n");
        builder.append("对称加密密钥：" + encoder.encode(symKey) + "\n");
        builder.append("Hash算法：" + hashAlg + "\n");
        if (user == 1) {
            builder.append("RSA算法公钥(n,e)：(" + rsaKey1.getPublicKey().getModule() + rsaKey1.getPublicKey().getPublicExponent() + ")\n");
            builder.append("RSA算法私钥(n,d)：(" + rsaKey1.getPrivateKey().getModule() + rsaKey1.getPrivateKey().getPrivateExponent() + ")\n");
        } else {
            builder.append("RSA算法公钥(n,e)：(" + rsaKey2.getPublicKey().getModule() + rsaKey2.getPublicKey().getPublicExponent() + ")\n");
            builder.append("RSA算法私钥(n,d)：(" + rsaKey2.getPrivateKey().getModule() + rsaKey2.getPrivateKey().getPrivateExponent() + ")\n");
        }
        return builder.toString();
    }

    public byte[] getDigest(byte[] msg) {
        byte[] digest = {};
        if (hashAlg.equals("MD5")) {
            MD5 md5 = new MD5();
            md5.update(msg);
            digest = md5.getDigest();
        } else if (hashAlg.equals("SHA224")) {
            SHA2.SHA224 sha224 = new SHA2.SHA224();
            sha224.update(msg);
            digest = sha224.getDigest();
        } else if (hashAlg.equals("SHA256")) {
            SHA2.SHA256 sha256 = new SHA2.SHA256();
            sha256.update(msg);
            digest = sha256.getDigest();
        } else if (hashAlg.equals("SHA384")) {
            SHA5.SHA384 sha384 = new SHA5.SHA384();
            sha384.update(msg);
            digest = sha384.getDigest();
        } else if (hashAlg.equals("SHA512")) {
            SHA5.SHA512 sha512 = new SHA5.SHA512();
            sha512.update(msg);
            digest = sha512.getDigest();
        }

        return digest;
    }

    /**
     * 对称加密
     */
    private byte[] symEnc(byte[] m, byte[] symKey) {
        if (symEncAlg.equals("DES")) {
            return new DES(symKey).encrypt(m);
        } else {
            return new AES(symKey).encrypt(m);
        }
    }

    public byte[] symDec(byte[] c) {
        if (symEncAlg.equals("DES")) {
            return new DES(symKey).decrypt(c);
        } else {
            return new AES(symKey).decrypt(c);
        }
    }

    /**
     * 发送方处理，将明文消息处理为E[K,M||E[RK1,H(M)]]||E[UK2,K]的形式，
     * 其中K为会话密钥，M为明文，RK1为发送方私钥，UK2为接收方公钥
     * @param m
     * @return
     */
    public String sendProcess(String m) {
        byte[] msg = m.getBytes();
        byte[] digest = getDigest(msg);
        byte[] signature = new byte[0];
        try {
            signature = new RSA(3, rsaKey1.getPrivateKey()).process(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] ukedKey = new byte[0];
        try {
            ukedKey = new RSA(1, rsaKey2.getPublicKey()).process(symKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] t = new byte[msg.length + signature.length];
        System.arraycopy(msg, 0, t, 0, msg.length);
        System.arraycopy(signature, 0, t, msg.length, signature.length);
        byte[] encrypted = symEnc(t, symKey);
        byte[] out = new byte[encrypted.length + ukedKey.length];
        System.arraycopy(encrypted, 0, out, 0, encrypted.length);
        System.arraycopy(ukedKey, 0, out, encrypted.length, ukedKey.length);
        senderMessage = encoder.encode(out);
        return senderMessage;
    }

    /**
     * 接收方解密操作，返回解密后明文，签名，会话密钥等信息
     * @param s
     * @return
     */
    public String receiverDecrypt(String s) {
        if (s.equals("")) {
            return "没有接收到任何消息！\n";
        }
        byte[] c = new byte[0];
        try {
            c = decoder.decodeBuffer(s);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] ukedKey = new byte[getByteLength(rsaKey2.getPrivateKey().getModule())];
        if (c.length < ukedKey.length) {
            return "消息遭到篡改，无法解密!\n";
        }
        System.arraycopy(c, c.length - ukedKey.length, ukedKey, 0, ukedKey.length);
        byte[] sessionKey = new byte[0];
        try {
            sessionKey = new RSA(2, rsaKey2.getPrivateKey()).process(ukedKey);
        } catch (Exception e) {
            return "消息遭到篡改，无法解密!\n";
        }
        byte[] t = new byte[c.length - ukedKey.length];
        if (t.length % blockLen != 0) {
            return "消息遭到篡改，无法解密!\n";
        }
        System.arraycopy(c, 0, t, 0, t.length);
        byte[] decrypted = symDec(t);
        byte[] signature = new byte[getByteLength(rsaKey1.getPublicKey().getModule())];
        System.arraycopy(decrypted, decrypted.length - signature.length, signature, 0, signature.length);
        byte[] digest = new byte[0];
        try {
            digest = new RSA(4, rsaKey1.getPublicKey()).process(signature);
        } catch (Exception e) {
            return "消息遭到篡改，无法解密!\n";
        }
        byte[] m = new byte[decrypted.length - signature.length];
        System.arraycopy(decrypted, 0, m, 0, m.length);

        StringBuilder builder = new StringBuilder();
        builder.append("解密得会话密钥：" + encoder.encode(sessionKey) + "\n");
        builder.append("解密得数字签名：" + encoder.encode(signature) + "\n");
        builder.append("解密得消息摘要：" + encoder.encode(digest) + "\n");
        builder.append("解密得明文：" + new String(m) + "\n");
        return builder.toString();
    }

    public String receiverVerify(String s) {
        if (s.equals("")) {
            return "没有接收到任何消息！\n";
        }
        byte[] c = new byte[0];
        try {
            c = decoder.decodeBuffer(s);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] ukedKey = new byte[getByteLength(rsaKey2.getPrivateKey().getModule())];
        if (c.length < ukedKey.length) {
            return "认证失败，消息遭到篡改！\n";
        }
        System.arraycopy(c, c.length - ukedKey.length, ukedKey, 0, ukedKey.length);
        byte[] sessionKey = new byte[0];
        try {
            sessionKey = new RSA(2, rsaKey2.getPrivateKey()).process(ukedKey);
        } catch (Exception e) {
            return "认证失败，消息遭到篡改！\n";
        }
        byte[] t = new byte[c.length - ukedKey.length];
        if (t.length % blockLen != 0) {
            return "认证失败，消息遭到篡改！\n";
        }
        System.arraycopy(c, 0, t, 0, t.length);
        byte[] decrypted;
        if (sessionKey.length == 8) {
            decrypted = new DES(sessionKey).decrypt(t);
        } else {
            decrypted = new AES(sessionKey).decrypt(t);
        }
        byte[] signature = new byte[getByteLength(rsaKey1.getPublicKey().getModule())];
        System.arraycopy(decrypted, decrypted.length - signature.length, signature, 0, signature.length);
        byte[] digest = new byte[0];
        try {
            digest = new RSA(4, rsaKey1.getPublicKey()).process(signature);
        } catch (Exception e) {
            return "认证失败，消息遭到篡改！";
        }
        byte[] m = new byte[decrypted.length - signature.length];
        System.arraycopy(decrypted, 0, m, 0, m.length);
        byte[] mdigest = getDigest(m);
        if (Arrays.equals(digest, mdigest)) {
            return "认证通过，消息没有遭到篡改！\n";
        } else {
            return "认证失败，消息遭到篡改！\n";
        }
    }

    private int getByteLength(BigInteger bi) {
        int bitLen = bi.bitLength();
        return (bitLen + 7) >> 3;
    }

    private static void printByteArray(byte[] array) {
        for (int i = 0; i < array.length; i++) {
            System.out.print("0x" + Integer.toHexString(array[i] & 0xFF) + " ");
        }
        System.out.println();
    }
}
