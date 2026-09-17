/* SPDX-License-Identifier: GPL-3.0-only
 * Synthetic types/constants for branch/lifetime tests. NOT QNX ABI headers.
 * Deliberately different family numbers catch accidental hardcoded values.
 */
#ifndef HEADUNIT_QNX_DIAGNOSTIC_TEST_API_H
#define HEADUNIT_QNX_DIAGNOSTIC_TEST_API_H
#define AF_INET 49
#define AF_INET6 66
#define SOCK_DGRAM 7
#define IFNAMSIZ 16
struct sockaddr { unsigned char sa_len, sa_family; char sa_data[14]; };
struct sockaddr_in { unsigned char sin_len, sin_family; unsigned short sin_port; unsigned char sin_addr[4]; char pad[8]; };
struct sockaddr_in6 { unsigned char sin6_len, sin6_family; unsigned short sin6_port; unsigned int flow; unsigned char sin6_addr[16]; unsigned int sin6_scope_id; };
struct ifaddrs { struct ifaddrs *ifa_next; char *ifa_name; unsigned int ifa_flags; struct sockaddr *ifa_addr; };
int diagnostic_test_socket(int, int, int);
int diagnostic_test_close(int);
int diagnostic_test_getifaddrs(struct ifaddrs **);
void diagnostic_test_freeifaddrs(struct ifaddrs *);
unsigned int diagnostic_test_if_nametoindex(const char *);
char *diagnostic_test_getenv(const char *);
int diagnostic_test_printf(const char *, ...);
int diagnostic_test_fflush(FILE *);
int diagnostic_test_ferror(FILE *);
#define socket diagnostic_test_socket
#define close diagnostic_test_close
#define getifaddrs diagnostic_test_getifaddrs
#define freeifaddrs diagnostic_test_freeifaddrs
#define if_nametoindex diagnostic_test_if_nametoindex
#define getenv diagnostic_test_getenv
#define printf diagnostic_test_printf
#define fflush diagnostic_test_fflush
#define ferror diagnostic_test_ferror
#endif
