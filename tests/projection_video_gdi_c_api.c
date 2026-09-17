/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_video_gdi.h"
int projection_video_gdi_c_api_test(void) {
    projection_video_gdi *owner=NULL;
    projection_video_gdi_config config={0};
    projection_video_sink sink=projection_video_gdi_sink(NULL);
    projection_session_resource resource={0}; uint64_t child=99;
    int ok=projection_video_gdi_create(&config,91,&owner)==IAP2_ARGUMENT && !owner &&
        sink.open(sink.context,91,&resource,&child)==IAP2_ARGUMENT && child==0 &&
        projection_video_gdi_paint(NULL,91,110)==IAP2_ARGUMENT;
    projection_video_gdi_close(NULL); projection_video_gdi_destroy(NULL); return ok;
}
