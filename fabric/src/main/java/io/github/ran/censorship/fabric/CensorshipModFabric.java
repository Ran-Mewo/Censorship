package io.github.ran.censorship.fabric;

import net.fabricmc.api.DedicatedServerModInitializer;

import io.github.ran.censorship.CensorshipMod;

public final class CensorshipModFabric implements DedicatedServerModInitializer {
    @Override
    public void onInitializeServer() {
        CensorshipMod.init();
    }
}
