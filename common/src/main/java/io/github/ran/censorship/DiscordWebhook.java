package io.github.ran.censorship;

import net.minecraft.server.level.ServerPlayer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.concurrent.CompletableFuture;

public class DiscordWebhook {
    private static final String WEBHOOK_FORMAT = """
                {
                    "embeds": [
                        {
                            "title": "Deleted Message",
                            "description": "%s",
                            "color": 4645612,
                            "fields": [
                                {
                                    "name": "Blocked Content",
                                    "value": "%s"
                                },
                                {
                                    "name": "Player",
                                    "value": "%s",
                                    "inline": true
                                },
                                {
                                    "name": "UUID",
                                    "value": "%s",
                                    "inline": true
                                }
                            ],
                            "thumbnail": {
                                "url": "https://minotar.net/avatar/%s"
                            },
                            "footer": {
                                "text": "Censorship Mod"
                            },
                            "timestamp": "%s"
                        }
                    ]
                }""";

    public static void sendWebhook(String webhookURL, ServerPlayer player, String contentIndicated, String blockedPhrase) {
        if (webhookURL.isBlank()) return;
        String username = player.getName().getString();
        String UUID = player.getUUID().toString();

        String message = String.format(WEBHOOK_FORMAT, contentIndicated.replace("§n", "__").replace("§r", "__"), blockedPhrase, username, UUID, UUID, OffsetDateTime.now());

        // Send the message to the webhook
        try (HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(webhookURL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(message))
                    .build();

            // Send asynchronously to not block the game thread
            CompletableFuture<HttpResponse<String>> future = client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
            future.thenAccept(response -> {});
        }
    }
}
