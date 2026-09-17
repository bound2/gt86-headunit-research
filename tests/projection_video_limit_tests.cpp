/* SPDX-License-Identifier: GPL-3.0-only */
/* Explicit white-box executable: lifetime-limit injection exists only here.
 * The separate normal tests link the actual production library without hooks.
 */
#include "../src/carplay/projection_video.cpp"
#include <iostream>

int main() {
    uint8_t key[32]{};
    projection_video_config cfg{640, 480, 1000, 2000, 2, 1};
    projection_video *v = nullptr;
    if (projection_video_create(&cfg, key, 17, 0, &v) != PROJECTION_VIDEO_MORE) return 1;
    std::unique_ptr<projection_video, decltype(&projection_video_destroy)> owned(v, projection_video_destroy);
    // Only a tagged empty record is needed to test the 64-bit boundary. Normal
    // config/SPS/media startup is covered by the production-library tests.
    if (projection_h264_create(17, 640, 480, &v->decoder) != PROJECTION_H264_MORE) return 2;
    v->counter = UINT64_MAX;
    std::array<uint8_t, 144> wire{}; wire[0] = 16;
    uint8_t nonce[12]{}; std::memset(nonce + 4, 0xff, 8);
    crypto_aead_ctx ctx; crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, wire.data() + 128, wire.data() + 128, wire.data(), 128, key, 0);
    crypto_wipe(&ctx, sizeof(ctx));
    size_t used = 0;
    if (projection_video_feed(v, 17, wire.data(), wire.size(), &used, 0) != PROJECTION_VIDEO_PACKET ||
        used != wire.size() || !v->exhausted || v->counter != UINT64_MAX) return 3;
    if (projection_video_feed(v, 17, wire.data(), wire.size(), &used, 0) != PROJECTION_VIDEO_LIMIT ||
        !v->dead || v->decoder || v->count || v->rx_used) return 4;
    for (uint8_t b : v->key) if (b) return 5;
    for (uint8_t b : v->wire) if (b) return 6;
    for (uint8_t b : v->plain) if (b) return 7;
    for (uint8_t b : v->scratch) if (b) return 8;
    if (projection_video_create(&cfg, key, 18, 0, &v) != PROJECTION_VIDEO_MORE) return 9;
    owned.reset(v); v->epoch = 64;
    std::array<uint8_t, 129> config{}; config[0] = 1; config[4] = 1;
    config[128] = 1; // Bare AVC discriminator: test the change limit, not a malformed wrapper.
    // Full valid 64-change/no-op/65th-change behavior is covered by public API tests.
    if (projection_video_feed(v, 18, config.data(), config.size(), &used, 0) != PROJECTION_VIDEO_LIMIT || !v->dead) return 10;
    std::cout << "white-box nonce exhaustion, close/wipe and configuration-epoch limit passed\n";
    return 0;
}
