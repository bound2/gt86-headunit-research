/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_h264.h"
#include "../third_party/openh264/ls_defines.h"
int projection_h264_c_api_test(void) {
    /* The same override compiled into the codec must support every byte offset. */
    uint8_t buffer[32], expected[32];
    const uint16_t v16 = 0xb271;
    const uint32_t v32 = 0xc3519372;
    const uint64_t v64 = UINT64_C(0x8473926150473625);
    for (size_t offset = 0; offset < 8; ++offset) {
        memset(buffer, 0x7a, sizeof(buffer)); memset(expected, 0x7a, sizeof(expected));
        memcpy(expected + offset, &v16, sizeof(v16)); ST16(buffer + offset, v16);
        if (memcmp(buffer, expected, sizeof(buffer)) || LD16(buffer + offset) != v16) return 0;
        memcpy(expected + offset, &v32, sizeof(v32)); ST32(buffer + offset, v32);
        if (memcmp(buffer, expected, sizeof(buffer)) || LD32(buffer + offset) != v32) return 0;
        memcpy(expected + offset, &v64, sizeof(v64)); ST64(buffer + offset, v64);
        if (memcmp(buffer, expected, sizeof(buffer)) || LD64(buffer + offset) != v64) return 0;
        ST16A2(buffer + offset, v16); if (LD16A2(buffer + offset) != v16) return 0;
        ST32A2(buffer + offset, v32); if (LD32A2(buffer + offset) != v32) return 0;
        ST32A4(buffer + offset, v32); if (LD32A4(buffer + offset) != v32) return 0;
        ST64A2(buffer + offset, v64); if (LD64A2(buffer + offset) != v64) return 0;
        ST64A4(buffer + offset, v64); if (LD64A4(buffer + offset) != v64) return 0;
        ST64A8(buffer + offset, v64); if (LD64A8(buffer + offset) != v64) return 0;
    }
    projection_h264 *owner = NULL;
    projection_h264_frame *frame = NULL;
    if (projection_h264_create(123, 640, 480, &owner) != PROJECTION_H264_MORE) return 0;
    int result = projection_h264_drain(owner, 123, &frame);
    projection_h264_frame_destroy(frame);
    projection_h264_destroy(owner);
    return result == PROJECTION_H264_END && frame == NULL;
}
