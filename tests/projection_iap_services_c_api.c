/* SPDX-License-Identifier: GPL-3.0-only; compile/link the public C ABI. */
#include "projection_iap_services.h"
int projection_iap_services_c_api_test(void) {
    projection_iap_services *s=0;
    projection_session_provider p=projection_iap_services_provider(s);
    return projection_iap_services_create(0,91,&s)==IAP2_ARGUMENT&&!s&&p.open&&p.start&&p.close&&p.poll&&p.next_delay;
}
