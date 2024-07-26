package com.janetfilter.plugins.powerrule;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class DSASignatureFilter {
    /**
     * 计算方法来源 https://linux.do/t/topic/32294
     * @param y
     * @param u2
     * @param p
     * @param t1
     * @param q
     * @param r
     */
    public static void testFilter(BigInteger y,BigInteger u2,BigInteger p,BigInteger t1,BigInteger q,BigInteger r) {
        BigInteger pq = p.multiply(q);
        BigInteger t1InvModPQ = t1.modInverse(pq);
        BigInteger result = r.multiply(t1InvModPQ).mod(pq);
        System.out.println("\n\n\n\n-------DSA power rule-------\n"+"EQUAL,"+y+","+u2+","+p+"->"+result+"\n------------------------\n\n\n\n");
    }
}
