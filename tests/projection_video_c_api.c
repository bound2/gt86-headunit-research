/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_video.h"
int projection_video_c_api_test(void) {
    uint8_t key[32] = {0};
    projection_video_config cfg = {640, 480, 1000, 2000, 2, 1};
    projection_video *v = NULL;
    projection_h264_frame *frame = NULL;
    projection_video_metadata meta;
    if (projection_video_create(&cfg, key, 25, 0, &v) != PROJECTION_VIDEO_MORE) return 0;
    int ok = projection_video_start(v, 25, 0) == PROJECTION_VIDEO_MORE &&
        projection_video_finish(v, 25, 0) == PROJECTION_VIDEO_END &&
        projection_video_take(v, 25, &frame, &meta, 0) == PROJECTION_VIDEO_END && frame == NULL;
    projection_h264_frame_destroy(frame); projection_video_destroy(v);
    return ok;
}
