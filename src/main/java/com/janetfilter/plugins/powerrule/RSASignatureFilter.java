package com.janetfilter.plugins.powerrule;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class RSASignatureFilter {
    public static void testFilter(byte[] data, RSAPublicKey pub,byte[] result) {
        System.out.println("\n\n\n\n-------RSA power rule-------\n"+"EQUAL,"+new BigInteger(1,data)+","+pub.getPublicExponent()+","+pub.getModulus()+"->"+new BigInteger(1,result)+"\n------------------------\n\n\n\n");
    }
}
