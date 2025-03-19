package io.github.ran.censorship.neoforge;

import net.neoforged.fml.common.Mod;

import io.github.ran.censorship.CensorshipMod;

@Mod(CensorshipMod.MOD_ID)
public final class CensorshipModNeoForge {
    public CensorshipModNeoForge() {
        // Run our common setup.
        CensorshipMod.init();
    }
}
