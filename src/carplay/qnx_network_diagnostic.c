/* SPDX-License-Identifier: GPL-3.0-only
 * A local network observation tool, NOT a CarPlay receiver or installer.
 * Default invocation makes no network queries. --inspect-network opens and
 * closes unbound sockets and enumerates interfaces; it never sends packets,
 * binds/listens, alters interfaces, or claims a USB device.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HEADUNIT_QNX_DIAGNOSTIC_TEST
/* Synthetic API model supplied only by the host test target, not a QNX SDK. */
#include "qnx_network_diagnostic_test_api.h"
#else
#if !defined(__QNXNTO__) || !defined(__arm__) || !defined(__ARMEL__)
#error This diagnostic requires a QNX little-endian ARM SDK
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
/* These corpus-specific checks detect a wrong SDK family; they do not prove
 * the installed 6.9.0WL runtime matches the later research corpus. */
typedef char headunit_pointer32[(sizeof(void *) == 4) ? 1 : -1];
typedef char headunit_ipv4_layout[(sizeof(struct sockaddr_in) == 16) ? 1 : -1];
typedef char headunit_ipv6_layout[(sizeof(struct sockaddr_in6) == 28 &&
    offsetof(struct sockaddr_in6, sin6_scope_id) == 24) ? 1 : -1];
#endif

#define HEADUNIT_DIAGNOSTIC_MAX_ENTRIES 128u

static void bytes_hex(const void *source, size_t count)
{
    const unsigned char *bytes = (const unsigned char *)source;
    size_t i;
    for (i = 0; i < count; ++i) (void)printf("%02x", (unsigned int)bytes[i]);
}

static int probe_socket(int family)
{
    int descriptor, error, closed;
    errno = 0;
    descriptor = socket(family, SOCK_DGRAM, 0);
    error = descriptor < 0 ? errno : 0;
    if (descriptor < 0) {
        (void)printf("socket family=%d created=0 errno=%d\n", family, error);
        return 1;
    }
    errno = 0;
    closed = close(descriptor);
    error = closed < 0 ? errno : 0;
    (void)printf("socket family=%d created=1 close_ok=%d errno=%d\n", family, closed == 0, error);
    /* Do not retry an ambiguous close or reuse its descriptor. */
    return closed != 0;
}

static int report_entry(const struct ifaddrs *entry, unsigned int number)
{
    size_t length = 0;
    unsigned int index;
    int error, incomplete = 0;
    const struct sockaddr *address = entry->ifa_addr;
    (void)printf("interface entry=%u name_hex=", number);
    if (entry->ifa_name) {
        while (length < IFNAMSIZ && entry->ifa_name[length]) ++length;
    }
    if (!length || length == IFNAMSIZ) {
        (void)printf("invalid lookup_index=0 lookup_errno=0");
        incomplete = 1;
    } else {
        bytes_hex(entry->ifa_name, length);
        /* This is a later lookup, not atomic with the address snapshot. */
        errno = 0;
        index = if_nametoindex(entry->ifa_name);
        error = index ? 0 : errno;
        (void)printf(" lookup_index=%u lookup_errno=%d", index, error);
        if (!index) incomplete = 1;
    }
    (void)printf(" flags=%u", (unsigned int)entry->ifa_flags);
    if (!address) {
        (void)printf(" address=none\n");
        return incomplete;
    }
    if (address->sa_len < offsetof(struct sockaddr, sa_data)) {
        (void)printf(" address=short_header length=%u\n", (unsigned int)address->sa_len);
        return 1;
    }
    (void)printf(" family=%u length=%u", (unsigned int)address->sa_family, (unsigned int)address->sa_len);
    if (address->sa_family == AF_INET && address->sa_len == sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)address;
        (void)printf(" raw_address_hex=");
        bytes_hex(&v4->sin_addr, sizeof(v4->sin_addr));
    } else if (address->sa_family == AF_INET6 && address->sa_len == sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)address;
        (void)printf(" raw_address_hex=");
        bytes_hex(&v6->sin6_addr, sizeof(v6->sin6_addr));
        (void)printf(" raw_scope=%lu", (unsigned long)v6->sin6_scope_id);
    } else if (address->sa_family == AF_INET || address->sa_family == AF_INET6) {
        (void)printf(" address=invalid_length");
        incomplete = 1;
    } else {
        (void)printf(" address=uninterpreted");
    }
    (void)printf("\n");
    return incomplete;
}

int headunit_qnx_network_diagnostic(int argc, char **argv)
{
    struct ifaddrs *head = NULL, *entry;
    unsigned int count = 0;
    int incomplete = 0, error;
    if (argc != 2 || !argv || !argv[1] || strcmp(argv[1], "--inspect-network")) {
        (void)printf("usage: qnx-network-diagnostic --inspect-network\n");
        (void)printf("No network queries performed. Not a CarPlay receiver or installation tool.\n");
        if (fflush(stdout) != 0 || ferror(stdout)) return 1;
        return argc == 1 ? 0 : 2;
    }
    (void)printf("headunit_network_diagnostic version=1 sock_override_present=%d\n", getenv("SOCK") != NULL);
    (void)printf("abi pointer_bytes=%u ipv4_bytes=%u ipv6_bytes=%u ipv6_scope_offset=%u af_inet=%d af_inet6=%d\n",
        (unsigned int)sizeof(void *), (unsigned int)sizeof(struct sockaddr_in),
        (unsigned int)sizeof(struct sockaddr_in6), (unsigned int)offsetof(struct sockaddr_in6, sin6_scope_id),
        AF_INET, AF_INET6);
    incomplete |= probe_socket(AF_INET);
    incomplete |= probe_socket(AF_INET6);
    errno = 0;
    if (getifaddrs(&head) != 0) {
        error = errno;
        (void)printf("snapshot obtained=0 errno=%d\n", error);
        /* A failed getifaddrs does not transfer a successful list to us. */
        incomplete = 1;
    } else {
        for (entry = head; entry && count < HEADUNIT_DIAGNOSTIC_MAX_ENTRIES; entry = entry->ifa_next) {
            incomplete |= report_entry(entry, count);
            ++count;
        }
        (void)printf("snapshot obtained=1 entries=%u truncated=%d\n", count, entry != NULL);
        if (entry) incomplete = 1;
        if (head) freeifaddrs(head);
    }
    (void)printf("result incomplete=%d phone_association_verified=0 listener_ready=0\n", incomplete != 0);
    if (fflush(stdout) != 0 || ferror(stdout)) return 1;
    return incomplete ? 1 : 0;
}

#ifndef HEADUNIT_QNX_DIAGNOSTIC_TEST
int main(int argc, char **argv) { return headunit_qnx_network_diagnostic(argc, argv); }
#endif
