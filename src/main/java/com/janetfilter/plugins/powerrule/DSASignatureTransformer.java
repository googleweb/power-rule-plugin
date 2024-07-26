package com.janetfilter.plugins.powerrule;


import com.janetfilter.core.plugin.MyTransformer;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.*;

import java.util.Iterator;

public class DSASignatureTransformer implements MyTransformer {
    @Override
    public String getHookClassName() {
        return "sun/security/provider/DSA";
    }

    @Override
    public byte[] transform(String className, byte[] classBytes, int order) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode();
        reader.accept(node, 0);

        for (MethodNode mn : node.methods) {
            if (mn.name.equals("generateV") && mn.desc.equals("(Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;)Ljava/math/BigInteger;")) {
                Iterator<AbstractInsnNode> it = mn.instructions.iterator();
                while (it.hasNext()){
                    AbstractInsnNode in = it.next();
                    //直接插到最后吧
                    if(Opcodes.ARETURN==in.getOpcode()){
                        //查看了jdk8和jdk21的DSA.class，两个modPow方法的参数和返回值的变量值索引都一样,这里直接用了，不再去严格匹配了
                        InsnList list = new InsnList();
                        //第二个modPow函数参数y.modPow(u2,p);hook第二个modPow的结果
                        list.add(new VarInsnNode(Opcodes.ALOAD, 1));
                        list.add(new VarInsnNode(Opcodes.ALOAD, 11));
                        list.add(new VarInsnNode(Opcodes.ALOAD, 2));
                        //第一个modPow函数返回值t1
                        list.add(new VarInsnNode(Opcodes.ALOAD, 12));
                        //入参q
                        list.add(new VarInsnNode(Opcodes.ALOAD, 3));
                        //入参r
                        list.add(new VarInsnNode(Opcodes.ALOAD, 6));
                        //传入以上六个参数
                        list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "com/janetfilter/plugins/powerrule/DSASignatureFilter", "testFilter", "(Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;)V", false));
                        mn.instructions.insertBefore(in,list);
                    }
                }

            }
        }

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }
}
