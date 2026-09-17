/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_video_pixels.h"
int projection_video_pixels_c_api_test(void) {
    uint8_t pixels[6]={16,235,16,235,128,128},out[16]={0};
    projection_h264_view view={{pixels,pixels+4,pixels+5},2,2,{2,1,1},91,0,6};
    projection_video_rect rect;
    return projection_video_bgra(&view,PROJECTION_VIDEO_BT601_LIMITED,out,sizeof(out),8)==0 &&
        out[0]==0 && out[3]==255 && out[4]==255 && out[7]==255 &&
        projection_video_fit(2,2,4,2,&rect)==0 && rect.x==1 && rect.width==2;
}
