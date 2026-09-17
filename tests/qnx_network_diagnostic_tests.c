/* SPDX-License-Identifier: GPL-3.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "qnx_network_diagnostic_test_api.h"
#undef printf
#undef fflush
#undef ferror
int headunit_qnx_network_diagnostic(int, char **);
static char output[65536];
static size_t used;
static struct ifaddrs *snapshot;
static unsigned int sockets, closes, lists, frees, lookups, envs;
static int socket_failure, close_failure, list_failure, index_failure, output_failure, override;
static int descriptor_base, opened[2], closed[2];
static void check(int condition) { if (!condition) { fprintf(stderr, "diagnostic check failed\n%s", output); exit(1); } }
static void reset(void) {
    used = 0; output[0] = 0; snapshot = NULL;
    sockets = closes = lists = frees = lookups = envs = 0;
    socket_failure = close_failure = list_failure = index_failure = output_failure = override = 0;
    descriptor_base = 9; opened[0] = opened[1] = closed[0] = closed[1] = 0;
}
int diagnostic_test_printf(const char *format, ...) {
    int count; va_list args;
    va_start(args, format);
    count = vsnprintf(output + used, sizeof(output) - used, format, args);
    va_end(args);
    check(count >= 0 && (size_t)count < sizeof(output) - used);
    used += (size_t)count;
    return output_failure ? -1 : count;
}
int diagnostic_test_fflush(FILE *stream) { check(stream == stdout); return output_failure ? EOF : 0; }
int diagnostic_test_ferror(FILE *stream) { check(stream == stdout); return output_failure; }
int diagnostic_test_socket(int family, int type, int protocol) {
    check(sockets < 2 && family == (sockets == 0 ? AF_INET : AF_INET6));
    check(type == SOCK_DGRAM && protocol == 0); ++sockets;
    if (socket_failure == (int)sockets) { errno = 97; return -1; }
    opened[sockets - 1] = 1;
    return descriptor_base + (int)sockets;
}
int diagnostic_test_close(int descriptor) {
    int index = descriptor - descriptor_base - 1;
    check(index >= 0 && index < 2 && opened[index] && !closed[index]);
    closed[index] = 1; ++closes;
    if (close_failure) { errno = 5; return -1; }
    return 0;
}
int diagnostic_test_getifaddrs(struct ifaddrs **head) {
    ++lists; check(head && *head == NULL);
    if (list_failure) { errno = 12; return -1; }
    *head = snapshot; return 0;
}
void diagnostic_test_freeifaddrs(struct ifaddrs *head) { check(head == snapshot && head); ++frees; }
unsigned int diagnostic_test_if_nametoindex(const char *name) {
    check(name && strlen(name) < IFNAMSIZ); ++lookups;
    if (index_failure) { errno = 6; return 0; }
    return 7;
}
char *diagnostic_test_getenv(const char *name) { check(!strcmp(name, "SOCK")); ++envs; return override ? "private-stack-path" : NULL; }
static int run(void) { char *args[] = {"qnx-network-diagnostic", "--inspect-network", NULL}; return headunit_qnx_network_diagnostic(2, args); }

static void test_opt_in(void) {
    char *args[] = {"diag", "--help", NULL};
    reset(); check(headunit_qnx_network_diagnostic(1, args) == 0);
    check(!sockets && !lists && !envs);
    check(headunit_qnx_network_diagnostic(2, args) == 2);
    check(!sockets && !lists && !envs);
    check(headunit_qnx_network_diagnostic(2, NULL) == 2);
}
static void test_empty_and_socket_failures(void) {
    int which;
    reset(); check(run() == 0); check(sockets == 2 && closes == 2 && lists == 1 && !frees);
    check(strstr(output, "entries=0 truncated=0") != NULL);
    reset(); descriptor_base = -1; check(run() == 0); check(closes == 2); /* fd 0 is valid. */
    for (which = 1; which <= 2; ++which) {
        reset(); socket_failure = which; check(run() == 1);
        check(sockets == 2 && closes == 1 && lists == 1 && !frees);
        check(strstr(output, "created=0 errno=97") != NULL);
    }
    reset(); close_failure = 1; check(run() == 1);
    check(closes == 2); check(strstr(output, "close_ok=0 errno=5") != NULL);
    reset(); list_failure = 1; check(run() == 1); check(!frees);
    check(strstr(output, "snapshot obtained=0 errno=12") != NULL);
}
static void test_addresses_and_scope_are_observations(void) {
    struct sockaddr_in v4 = {0}; struct sockaddr_in6 v6 = {0};
    struct sockaddr unknown = {0}; struct ifaddrs entries[4] = {{0}};
    unsigned int i;
    reset(); v4.sin_len = sizeof(v4); v4.sin_family = AF_INET;
    v4.sin_addr[0] = 192; v4.sin_addr[1] = 0; v4.sin_addr[2] = 2; v4.sin_addr[3] = 1;
    v6.sin6_len = sizeof(v6); v6.sin6_family = AF_INET6;
    v6.sin6_addr[0] = 0xfe; v6.sin6_addr[1] = 0x80;
    v6.sin6_addr[3] = 7; v6.sin6_addr[15] = 1; v6.sin6_scope_id = 7;
    unknown.sa_len = sizeof(unknown); unknown.sa_family = 99;
    for (i = 0; i < 4; ++i) { entries[i].ifa_name = "ncm0"; entries[i].ifa_flags = 65; if (i < 3) entries[i].ifa_next = &entries[i + 1]; }
    entries[0].ifa_addr = (struct sockaddr *)&v4; entries[1].ifa_addr = (struct sockaddr *)&v6;
    entries[2].ifa_addr = &unknown; snapshot = entries;
    override = 1; check(run() == 0); check(frees == 1 && lookups == 4);
    check(strstr(output, "raw_address_hex=c0000201") != NULL);
    check(strstr(output, "raw_address_hex=fe800007000000000000000000000001 raw_scope=7") != NULL);
    check(strstr(output, "address=uninterpreted") && strstr(output, "address=none"));
    check(strstr(output, "sock_override_present=1") && !strstr(output, "private-stack-path"));
    check(strstr(output, "phone_association_verified=0 listener_ready=0") != NULL);
    check(v6.sin6_addr[3] == 7 && v6.sin6_scope_id == 7); /* Not a wire-address normalizer. */
}
static void test_invalid_names_lengths_and_index(void) {
    struct ifaddrs entry = {0}; struct sockaddr address = {0};
    char long_name[IFNAMSIZ]; int i;
    memset(long_name, 'X', sizeof(long_name));
    for (i = 0; i < 3; ++i) {
        reset(); entry.ifa_name = i == 0 ? NULL : (i == 1 ? "" : long_name); snapshot = &entry;
        check(run() == 1 && !lookups && frees == 1);
        check(strstr(output, "name_hex=invalid") != NULL);
    }
    reset(); entry.ifa_name = "x\n\x1b"; snapshot = &entry;
    check(run() == 0); check(strstr(output, "name_hex=780a1b") != NULL);
    reset(); entry.ifa_name = "ncm0"; entry.ifa_addr = &address; snapshot = &entry;
    check(run() == 1); check(strstr(output, "address=short_header") != NULL);
    for (i = 0; i < 2; ++i) {
        reset(); address.sa_len = 2; address.sa_family = i ? AF_INET6 : AF_INET; snapshot = &entry;
        check(run() == 1); check(strstr(output, "address=invalid_length") != NULL);
    }
    reset(); entry.ifa_addr = NULL; snapshot = &entry; index_failure = 1;
    check(run() == 1); check(strstr(output, "lookup_index=0 lookup_errno=6") != NULL);
    check(frees == 1);
}
static void test_bounds_and_output_failure(void) {
    struct ifaddrs entries[129] = {{0}}; unsigned int i;
    for (i = 0; i < 129; ++i) { entries[i].ifa_name = "ncm0"; if (i < 128) entries[i].ifa_next = &entries[i + 1]; }
    reset(); snapshot = entries; check(run() == 1);
    check(lookups == 128 && frees == 1); check(strstr(output, "entries=128 truncated=1") != NULL);
    reset(); entries[127].ifa_next = NULL; snapshot = entries; check(run() == 0);
    check(lookups == 128 && frees == 1); check(strstr(output, "entries=128 truncated=0") != NULL);
    reset(); snapshot = entries; output_failure = 1; check(run() == 1);
    check(closes == 2 && frees == 1);
    reset(); entries[0].ifa_next = NULL; snapshot = entries; output_failure = 1;
    check(run() == 1); check(closes == 2 && frees == 1);
}
int main(void) {
    test_opt_in(); test_empty_and_socket_failures(); test_addresses_and_scope_are_observations();
    test_invalid_names_lengths_and_index(); test_bounds_and_output_failure();
    puts("PASS: five synthetic QNX diagnostic groups; no native ABI/runtime verification"); return 0;
}
