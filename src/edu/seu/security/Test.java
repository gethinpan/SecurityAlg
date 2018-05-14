package edu.seu.security;

import static java.lang.System.*;

public class Test {
    public static void main(String[] args) {
        byte b = (byte)0x89;
        out.println(b);
        out.println(Integer.toBinaryString(b));
    }
}
