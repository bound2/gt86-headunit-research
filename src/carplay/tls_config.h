/* SPDX-License-Identifier: GPL-3.0-only
 * Appended to pinned Mbed TLS 3.6.7 defaults. Separate hosted crypto build;
 * not the freestanding ARM protocol library or a QNX platform configuration.
 */
#undef MBEDTLS_NET_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_DEBUG_C
#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_SRTP
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_SESSION_TICKETS
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_RENEGOTIATION
