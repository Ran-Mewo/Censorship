package io.github.ran.censorship;

import com.craftjakob.configapi.config.ConfigBuilder;
import com.craftjakob.configapi.config.ConfigValueTypes;
import com.craftjakob.configapi.config.IConfigurator;

public class CensorshipConfig implements IConfigurator {
    public static final String DEFAULT_REGEX_URL = "https://gitlab.com/distant-horizons-team/yagpdb-regex-censor/-/raw/main/discord_bot_censor_code_merge.cs";

    // Settings
    public static ConfigValueTypes.BooleanValue kickPlayer;
    public static ConfigValueTypes.StringValue discordWebhookURL;

    // Advanced
    public static ConfigValueTypes.StringValue regexURL;
    public static ConfigValueTypes.BooleanValue debugMode;

    @Override
    public void configure(ConfigBuilder configBuilder) {
        configBuilder.push("Settings");
        kickPlayer = configBuilder.comment("Whether to kick the player or send them a warning message").define("kickPlayer", true);
        discordWebhookURL = configBuilder.comment("Log messages to a Discord webhook").define("discordWebhookURL", "");

        configBuilder.push("Advanced");
        regexURL = configBuilder.comment("DO NOT TOUCH | URL to fetch the regex from").define("regexURL", DEFAULT_REGEX_URL);
        debugMode = configBuilder.comment("Show debug logs for the regex parser").define("debugMode", false);
    }
}
