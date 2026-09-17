/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_video_pixels.h"
static uint8_t channel(int32_t value) {
    if(value<=0) return 0;
    if(value>=255*65536) return 255;
    return (uint8_t)((value+32768)/65536);
}
int projection_video_bgra(const projection_h264_view *v,enum projection_video_color color,
                          uint8_t *out,size_t capacity,size_t stride) {
    /* Q16 coefficients derived from Kr/Kb, not the lower-precision Q8 shortcut.
     * Columns: luma, red/V, green/U, green/V, blue/U, luma offset. */
    static const int32_t coefficients[4][6]={
        {76309,104597,25675,53279,132201,16},
        {65536,91881,22553,46802,116130,0},
        {76309,117489,13975,34925,138438,16},
        {65536,103206,12276,30679,121609,0}
    };
    size_t area,bytes,needed; uintptr_t base,dest; const int32_t *c; uint32_t y,x;
    if(!v||!out||color<1||color>4||!v->plane[0]||!v->plane[1]||!v->plane[2]||
       v->width<2||v->height<2||v->width>PROJECTION_H264_MAX_WIDTH||v->height>PROJECTION_H264_MAX_HEIGHT||
       (v->width&1)||(v->height&1)||v->stride[0]!=v->width||v->stride[1]!=v->width/2||v->stride[2]!=v->width/2) return -1;
    area=(size_t)v->width*v->height; bytes=area+area/2; base=(uintptr_t)v->plane[0]; dest=(uintptr_t)out;
    if(v->bytes!=bytes||base>UINTPTR_MAX-bytes||(uintptr_t)v->plane[1]!=base+area||
       (uintptr_t)v->plane[2]!=base+area+area/4||stride<(size_t)v->width*4||
       stride>(SIZE_MAX-(size_t)v->width*4)/(v->height-1)) return -1;
    needed=(v->height-1)*stride+(size_t)v->width*4;
    if(capacity<needed||dest>UINTPTR_MAX-needed||
       (dest<=base ? base-dest<needed : dest-base<bytes)) return -1;
    c=coefficients[color-1];
    for(y=0;y<v->height;++y) for(x=0;x<v->width;++x) {
        size_t uv=(size_t)(y/2)*(v->width/2)+x/2,at=(size_t)y*stride+x*4;
        int32_t luma=((int32_t)v->plane[0][(size_t)y*v->width+x]-c[5])*c[0];
        int32_t u=(int32_t)v->plane[1][uv]-128,vv=(int32_t)v->plane[2][uv]-128;
        out[at]=channel(luma+c[4]*u); out[at+1]=channel(luma-c[2]*u-c[3]*vv);
        out[at+2]=channel(luma+c[1]*vv); out[at+3]=255;
    }
    return 0;
}
int projection_video_fit(uint32_t w,uint32_t h,uint32_t tw,uint32_t th,projection_video_rect *out) {
    projection_video_rect r={0,0,0,0};
    if(!out||!w||!h||w>PROJECTION_H264_MAX_WIDTH||h>PROJECTION_H264_MAX_HEIGHT||!tw||!th||tw>4096||th>4096) return -1;
    if((uint64_t)w*th>(uint64_t)h*tw) { r.width=tw; r.height=(uint32_t)((uint64_t)h*tw/w); if(!r.height) r.height=1; }
    else { r.height=th; r.width=(uint32_t)((uint64_t)w*th/h); if(!r.width) r.width=1; }
    r.x=(tw-r.width)/2; r.y=(th-r.height)/2; *out=r; return 0;
}
