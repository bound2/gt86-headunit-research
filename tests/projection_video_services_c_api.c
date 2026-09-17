/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_video_services.h"
int projection_video_services_c_api_test(void) {
    projection_video_services *service = NULL;
    projection_video_services_config config = {0};
    projection_session_provider provider = projection_video_services_provider(NULL);
    projection_session_endpoint endpoint;
    projection_session_keys keys = {0};
    projection_session_resource request = {0};
    int ok = projection_video_services_create(&config, 91, &service) == IAP2_ARGUMENT && !service &&
        provider.open(provider.context, 91, &request, 0, &keys, &endpoint) == IAP2_ARGUMENT && !endpoint.lease &&
        projection_video_services_poll(NULL, 91) == IAP2_ARGUMENT &&
        projection_video_services_next_delay(NULL, 91) == UINT32_MAX &&
        projection_video_services_error(NULL) == IAP2_ARGUMENT;
    projection_video_services_close(NULL);
    projection_video_services_destroy(NULL);
    return ok;
}
