package io.github.ran.censorship;

import com.craftjakob.configapi.config.Config;
import com.craftjakob.configapi.config.ConfigRegister;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class CensorshipMod {
    public static final String MOD_ID = "censorship";
    public static final String CENSOR_FORMAT = """
    §l§c[Message Deleted]§r
    Be nice, keep the chat PG.
    Attempting to circumvent this may cause the blocks to become more strict.
    
    §bYour Message:§r
    %s
    
    §bBlocked Content:§r
    %s""";
    public static final Logger LOGGER = LogManager.getLogger("Censorship");

    public static void init() {
        ConfigRegister.get().registerConfig(MOD_ID, Config.ConfigType.COMMON, CensorshipConfig::new, MOD_ID);
        YAGPDBParser.loadParser(CensorshipConfig.regexURL.getValue(), CensorshipConfig.debugMode.getValue());
    }
}
