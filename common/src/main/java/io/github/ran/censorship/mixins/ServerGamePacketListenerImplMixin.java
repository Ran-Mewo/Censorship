package io.github.ran.censorship.mixins;

import io.github.ran.censorship.CensorshipConfig;
import io.github.ran.censorship.CensorshipMod;
import io.github.ran.censorship.DiscordWebhook;
import io.github.ran.censorship.YAGPDBParser;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.game.ServerboundChatPacket;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(value = ServerGamePacketListenerImpl.class, priority = Integer.MAX_VALUE - 1000)
public abstract class ServerGamePacketListenerImplMixin {
    @Shadow public ServerPlayer player;

    @Inject(method = "handleChat", cancellable = true, at = @At("HEAD"))
    private void handleChat(ServerboundChatPacket serverboundChatPacket, CallbackInfo ci) {
        var indicatedCensoredContent = YAGPDBParser.instance.findCensoredContent_Indicated(serverboundChatPacket.message());
        if (indicatedCensoredContent.match == null) return;
        ci.cancel();

        var warningMessage = Component.literal(String.format(CensorshipMod.CENSOR_FORMAT, indicatedCensoredContent.indication, indicatedCensoredContent.match));
        DiscordWebhook.sendWebhook(CensorshipConfig.discordWebhookURL.getValue(), player, indicatedCensoredContent.indication, indicatedCensoredContent.match);

        if (CensorshipConfig.kickPlayer.isSameValue(true)) {
            player.connection.disconnect(warningMessage);
            return;
        }
        player.sendSystemMessage(warningMessage);
    }
}
