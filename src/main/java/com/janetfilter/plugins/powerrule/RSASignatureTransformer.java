package com.janetfilter.plugins.powerrule;


import com.janetfilter.core.plugin.MyTransformer;
import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.Opcodes;
import jdk.internal.org.objectweb.asm.tree.*;

public class RSASignatureTransformer implements MyTransformer {
    @Override
    public String getHookClassName() {
        return "sun/security/rsa/RSASignature";
    }

    @Override
    public byte[] transform(String className, byte[] classBytes, int order) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode(Opcodes.ASM5);
        reader.accept(node, 0);

        for (MethodNode mn : node.methods) {
            if (mn.name.equals("engineVerify") && mn.desc.equals("([B)Z")) {
                InsnList instructions = mn.instructions;
                for (int i = 0; i < instructions.size(); i++) {
                    if (instructions.get(i) instanceof MethodInsnNode && instructions.get(i + 1) instanceof VarInsnNode) {
                        MethodInsnNode methodInsnNode = (MethodInsnNode) instructions.get(i);
                        VarInsnNode varInsnNode = (VarInsnNode) instructions.get(i + 1);
                        if (methodInsnNode.owner.equals("sun/security/rsa/RSASignature") && methodInsnNode.name.equals("getDigestValue") && methodInsnNode.desc.equals("()[B") && varInsnNode.getOpcode() == Opcodes.ASTORE) {

                            InsnList list = new InsnList();
                            //函数入参
                            list.add(new VarInsnNode(Opcodes.ALOAD, 1));
                            //publicKey
                            list.add(new VarInsnNode(Opcodes.ALOAD, 0));
                            list.add(new FieldInsnNode(Opcodes.GETFIELD, "sun/security/rsa/RSASignature", "publicKey", "Ljava/security/interfaces/RSAPublicKey;"));
                            //getDigestValue,digest计算后的真实值
                            //先构造ASN.1格式数据
                            list.add(new VarInsnNode(Opcodes.ALOAD, 0));
                            list.add(new FieldInsnNode(Opcodes.GETFIELD, "sun/security/rsa/RSASignature", "digestOID", "Lsun/security/util/ObjectIdentifier;"));
                            list.add(new VarInsnNode(Opcodes.ALOAD, varInsnNode.var));
                            list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "sun/security/rsa/RSASignature", "encodeSignature", "(Lsun/security/util/ObjectIdentifier;[B)[B", false));
                            //填充
                            list.add(new VarInsnNode(Opcodes.ALOAD, 0));
                            list.add(new FieldInsnNode(Opcodes.GETFIELD, "sun/security/rsa/RSASignature", "padding", "Lsun/security/rsa/RSAPadding;"));
                            list.add(new InsnNode(Opcodes.SWAP));
                            list.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "sun/security/rsa/RSAPadding", "pad", "([B)[B", false));
                            //传入以上三个参数
                            list.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "com/janetfilter/plugins/powerrule/RSASignatureFilter", "testFilter", "([BLjava/security/interfaces/RSAPublicKey;[B)V", false));
                            mn.instructions.insert(instructions.get(i + 1), list);
                        }
                    }
                }
            }
        }

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }
}
