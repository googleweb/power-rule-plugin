package com.janetfilter.plugins.powerrule;

import com.janetfilter.core.plugin.MyTransformer;
import com.janetfilter.core.plugin.PluginEntry;

import java.util.ArrayList;
import java.util.List;

public class PowerRule implements PluginEntry {
    private final List<MyTransformer> transformers = new ArrayList<>();

    public PowerRule() {
        transformers.add(new RSASignatureTransformer());
        transformers.add(new DSASignatureTransformer());
    }

    @Override
    public String getName() {
        return "PowerRule";
    }

    @Override
    public String getAuthor() {
        return "googleweb";
    }

    @Override
    public String getVersion() {
        return "v1.0";
    }

    @Override
    public String getDescription() {
        return "Generate result replcae rule for plugin-power";
    }

    @Override
    public List<MyTransformer> getTransformers() {
        return transformers;
    }
}
