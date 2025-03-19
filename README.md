# Censorship

A server-side Minecraft mod that helps maintain chat civility by filtering inappropriate language and content.

## About

Censorship is primarily designed for the Distant Horizons SMP server. It uses the exact same regex filters that are used in the Distant Horizons Discord server to ensure consistent moderation.

## Configuration

After the first run, a configuration file will be generated. You can adjust the following settings:

```
[Settings]
  # Whether to kick the player or send them a warning message
  kickPlayer = true
  
  # Log messages to a Discord webhook
  discordWebhookURL = ""

  [Advanced]
    # DO NOT TOUCH | URL to fetch the regex from
    regexURL = "https://gitlab.com/distant-horizons-team/yagpdb-regex-censor/-/raw/main/discord_bot_censor_code_merge.cs"
    # Show debug logs for the regex parser
    debugMode = false
```

## Credits

- YAGPDB Regex Censor maintained by the Distant Horizons team