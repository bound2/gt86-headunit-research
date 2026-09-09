/* SPDX-License-Identifier: GPL-3.0-only */
#include "lockdown_tls.h"
#include <mbedtls/version.h>
#include <mbedtls/platform_util.h>
#include <string.h>
#if MBEDTLS_VERSION_NUMBER != 0x03060700
#error Review the TLS dependency upgrade and tests before changing this pin.
#endif
static const int suites[] = { MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 0 };
static int live(const lockdown_tls *t) { return t && t->initialized && (t->state == LOCKDOWN_TLS_HANDSHAKE || t->state == LOCKDOWN_TLS_OPEN); }
static void free_crypto(lockdown_tls *t) {
    mbedtls_ssl_free(&t->ssl); mbedtls_ssl_config_free(&t->ssl_config);
    mbedtls_x509_crt_free(&t->root); mbedtls_x509_crt_free(&t->host_certificate);
    mbedtls_x509_crt_free(&t->device); mbedtls_pk_free(&t->host_key);
    mbedtls_platform_zeroize(t->tx, sizeof t->tx); mbedtls_platform_zeroize(t->rx, sizeof t->rx);
    mbedtls_platform_zeroize(t->session_id, sizeof t->session_id); t->session_id_size = 0;
    t->tx_size = t->rx_size = t->rx_offset = 0;
}
static int stop(lockdown_tls *t, enum lockdown_tls_reason reason, int error) {
    if (live(t)) {
        enum usbmux_connection_state state;
        t->state = LOCKDOWN_TLS_DEAD; t->reason = reason; t->last_error = error;
        if (!usbmux_dispatcher_state(t->dispatcher, &t->handle, &state)) usbmux_dispatcher_close(t->dispatcher);
        free_crypto(t);
    }
    return LOCKDOWN_TLS_CLOSED;
}
static int tick(lockdown_tls *t, uint64_t now) {
    enum usbmux_connection_state state; int status;
    if (!t || !t->initialized) return IAP2_ARGUMENT;
    if (!live(t)) return LOCKDOWN_TLS_CLOSED;
    status = usbmux_dispatcher_state(t->dispatcher, &t->handle, &state);
    if (status) return stop(t, status == USBMUX_DISPATCHER_STALE ? LOCKDOWN_TLS_REASON_STALE : LOCKDOWN_TLS_REASON_TRANSPORT, status);
    if (now < t->now || now < t->dispatcher->now) return IAP2_ARGUMENT;
    t->now = now;
    if ((t->state == LOCKDOWN_TLS_HANDSHAKE && now - t->started_at >= t->config.handshake_ms) ||
        (t->tx_size && now - t->write_at >= t->config.write_ms) ||
        (t->rx_size && now - t->held_at >= t->config.hold_ms))
        return stop(t, LOCKDOWN_TLS_REASON_DEADLINE, LOCKDOWN_TLS_CLOSED);
    status = usbmux_dispatcher_check(t->dispatcher, now);
    if (status) return stop(t, LOCKDOWN_TLS_REASON_TRANSPORT, status);
    if (state != USBMUX_CONNECTION_OPEN) return stop(t, LOCKDOWN_TLS_REASON_TRANSPORT, IAP2_END);
    return IAP2_OK;
}
static int send_cipher(void *context, const unsigned char *bytes, size_t size) {
    lockdown_tls *t = (lockdown_tls *)context; size_t n = 0; int status;
    if (!t->send_budget) return MBEDTLS_ERR_SSL_WANT_WRITE;
    t->send_budget = 0; if (size > LOCKDOWN_TLS_CHUNK) size = LOCKDOWN_TLS_CHUNK;
    status = usbmux_dispatcher_write(t->dispatcher, &t->handle, bytes, size, &n, t->now);
    if (status != IAP2_OK && status != IAP2_MORE && status != USBMUX_DISPATCHER_BUSY) {
        t->transport_error = status; return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return n ? (int)n : MBEDTLS_ERR_SSL_WANT_WRITE;
}
static int receive_cipher(void *context, unsigned char *bytes, size_t size) {
    lockdown_tls *t = (lockdown_tls *)context; size_t n = 0; int status;
    if (!t->receive_budget) return MBEDTLS_ERR_SSL_WANT_READ;
    t->receive_budget = 0; if (size > LOCKDOWN_TLS_CHUNK) size = LOCKDOWN_TLS_CHUNK;
    status = usbmux_dispatcher_read(t->dispatcher, &t->handle, bytes, size, &n, t->now);
    if (status == IAP2_END) { t->truncated = 1; return MBEDTLS_ERR_SSL_CONN_EOF; }
    if (status != IAP2_OK && status != IAP2_MORE) { t->transport_error = status; return MBEDTLS_ERR_SSL_INTERNAL_ERROR; }
    return n ? (int)n : MBEDTLS_ERR_SSL_WANT_READ;
}
static int verify_device(void *context, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    lockdown_tls *t = (lockdown_tls *)context;
    if (depth == 0) {
        t->peer_matched = crt->raw.len == t->device.raw.len && !memcmp(crt->raw.p, t->device.raw.p, crt->raw.len);
        if (!t->peer_matched) *flags |= MBEDTLS_X509_BADCERT_OTHER;
    }
    return 0; /* Never clear chain/time/key-usage/signature validation failures. */
}
void lockdown_tls_default_config(lockdown_tls_config *c) { if (c) { c->handshake_ms = 10000; c->write_ms = c->hold_ms = 5000; } }
static int body_ok(lockdown_body b, size_t limit) { return b.data && b.size && b.size <= limit; }
static int parse_certificates(mbedtls_x509_crt *crt, lockdown_body body) {
    int status = mbedtls_x509_crt_parse(crt, body.data, body.size);
    /* Positive parse counts mean a partially invalid PEM chain, never BUSY or
     * successful application progress in this API's shared status namespace. */
    return status > 0 ? MBEDTLS_ERR_X509_INVALID_FORMAT : status;
}
int lockdown_tls_init(lockdown_tls *t, lockdown_tls_handoff *h, const lockdown_tls_credentials *creds,
                      const lockdown_tls_config *config, uint64_t now) {
    enum usbmux_connection_state state; const usbmux_connection *conn; int status;
    if (!t || t->initialized || !h || !h->dispatcher || !h->session_id_size || h->session_id_size > 256 ||
        !creds || !creds->random || !config || !config->handshake_ms || config->handshake_ms > 60000 ||
        !config->write_ms || config->write_ms > 60000 || !config->hold_ms || config->hold_ms > 60000 ||
        !body_ok(creds->root, 32768) || !body_ok(creds->host_certificate, 32768) ||
        !body_ok(creds->host_private_key, 16384) || !body_ok(creds->device_der, 16384)) return IAP2_ARGUMENT;
    status = usbmux_dispatcher_state(h->dispatcher, &h->handle, &state); if (status) return status;
    conn = h->dispatcher->connections[h->handle.slot];
    /* A final plaintext receive ACK may still be queued by handoff. It carries
     * no application bytes and must drain in normal dispatcher order. */
    if (state != USBMUX_CONNECTION_OPEN || conn->peer_fin || conn->fin_requested || conn->tx_payload || conn->flight_count) return LOCKDOWN_TLS_BUSY;
    if (now < h->dispatcher->now || now < conn->now) return IAP2_ARGUMENT;
    memset(t, 0, sizeof *t);
    mbedtls_ssl_init(&t->ssl); mbedtls_ssl_config_init(&t->ssl_config);
    mbedtls_x509_crt_init(&t->root); mbedtls_x509_crt_init(&t->host_certificate); mbedtls_x509_crt_init(&t->device); mbedtls_pk_init(&t->host_key);
    status = parse_certificates(&t->root, creds->root); if (status) goto fail;
    status = parse_certificates(&t->host_certificate, creds->host_certificate); if (status) goto fail;
    status = mbedtls_x509_crt_parse_der(&t->device, creds->device_der.data, creds->device_der.size); if (status) goto fail;
    if (t->device.raw.len != creds->device_der.size) { status = IAP2_ARGUMENT; goto fail; }
    status = mbedtls_pk_parse_key(&t->host_key, creds->host_private_key.data, creds->host_private_key.size, NULL, 0, creds->random, creds->random_context); if (status) goto fail;
    status = mbedtls_pk_check_pair(&t->host_certificate.pk, &t->host_key, creds->random, creds->random_context); if (status) goto fail;
    status = mbedtls_ssl_config_defaults(&t->ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT); if (status) goto fail;
    mbedtls_ssl_conf_min_tls_version(&t->ssl_config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&t->ssl_config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(&t->ssl_config, suites);
    mbedtls_ssl_conf_authmode(&t->ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&t->ssl_config, &t->root, NULL);
    mbedtls_ssl_conf_verify(&t->ssl_config, verify_device, t);
    mbedtls_ssl_conf_rng(&t->ssl_config, creds->random, creds->random_context);
    status = mbedtls_ssl_conf_own_cert(&t->ssl_config, &t->host_certificate, &t->host_key); if (status) goto fail;
    status = mbedtls_ssl_setup(&t->ssl, &t->ssl_config); if (status) goto fail;
    /* A USB pairing identity is not a DNS name. Exact DER pin is mandatory. */
    status = mbedtls_ssl_set_hostname(&t->ssl, NULL); if (status) goto fail;
    mbedtls_ssl_set_bio(&t->ssl, t, send_cipher, receive_cipher, NULL);
    t->dispatcher = h->dispatcher; t->handle = h->handle; t->config = *config;
    memcpy(t->session_id, h->session_id, h->session_id_size); t->session_id_size = h->session_id_size;
    t->now = t->started_at = now; t->state = LOCKDOWN_TLS_HANDSHAKE; t->initialized = 1; t->again = 1;
    memset(h, 0, sizeof *h); return IAP2_OK;
fail:
    free_crypto(t); memset(t, 0, sizeof *t); return status;
}
int lockdown_tls_poll(lockdown_tls *t, uint64_t now) {
    int status = tick(t, now), transport;
    if (status) return status;
    transport = usbmux_dispatcher_poll(t->dispatcher, now);
    if (transport != IAP2_OK && transport != IAP2_MORE && transport != USBMUX_DISPATCHER_CONTROL)
        return stop(t, LOCKDOWN_TLS_REASON_TRANSPORT, transport);
    t->send_budget = t->receive_budget = 1; t->transport_error = t->truncated = t->again = 0;
    if (t->state == LOCKDOWN_TLS_HANDSHAKE) {
        status = mbedtls_ssl_handshake_step(&t->ssl);
        if (!status && mbedtls_ssl_is_handshake_over(&t->ssl)) {
            if (!t->peer_matched || mbedtls_ssl_get_verify_result(&t->ssl)) return stop(t, LOCKDOWN_TLS_REASON_CRYPTO, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
            t->state = LOCKDOWN_TLS_OPEN;
        }
    } else if (t->tx_size) {
        status = mbedtls_ssl_write(&t->ssl, t->tx, t->tx_size);
        if (status > 0) {
            if ((size_t)status != t->tx_size) return stop(t, LOCKDOWN_TLS_REASON_CRYPTO, MBEDTLS_ERR_SSL_INTERNAL_ERROR);
            mbedtls_platform_zeroize(t->tx, t->tx_size); t->tx_size = 0; status = 0;
        }
    } else if (!t->rx_size) {
        status = mbedtls_ssl_read(&t->ssl, t->rx, sizeof t->rx);
        if (status > 0) { t->rx_size = (size_t)status; t->rx_offset = 0; t->held_at = now; status = 0; }
        else if (!status) return stop(t, LOCKDOWN_TLS_REASON_TRUNCATED, MBEDTLS_ERR_SSL_CONN_EOF);
    } else return transport;
    if (t->truncated) return stop(t, LOCKDOWN_TLS_REASON_TRUNCATED, status);
    if (t->transport_error) return stop(t, LOCKDOWN_TLS_REASON_TRANSPORT, t->transport_error);
    if (status == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return stop(t, LOCKDOWN_TLS_REASON_PEER_CLOSE, status);
    if (status && status != MBEDTLS_ERR_SSL_WANT_READ && status != MBEDTLS_ERR_SSL_WANT_WRITE) return stop(t, LOCKDOWN_TLS_REASON_CRYPTO, status);
    t->again = !status;
    return transport == USBMUX_DISPATCHER_CONTROL ? transport : (!status ? IAP2_OK : IAP2_MORE);
}
int lockdown_tls_write(lockdown_tls *t, const uint8_t *data, size_t size, uint64_t now) {
    int status;
    if (!data || !size || size > LOCKDOWN_TLS_WRITE_LIMIT) return IAP2_ARGUMENT;
    status = tick(t, now); if (status) return status;
    if (t->state != LOCKDOWN_TLS_OPEN || t->tx_size) return LOCKDOWN_TLS_BUSY;
    if (t->dispatcher->connections[t->handle.slot]->peer_fin) return stop(t, LOCKDOWN_TLS_REASON_TRUNCATED, IAP2_END);
    memcpy(t->tx, data, size); t->tx_size = size; t->write_at = now; t->again = 1; return IAP2_OK;
}
int lockdown_tls_read(lockdown_tls *t, uint8_t *out, size_t capacity, size_t *size, uint64_t now) {
    size_t n; int status; if (size) *size = 0;
    if (!out || !capacity || !size) return IAP2_ARGUMENT;
    status = tick(t, now); if (status) return status;
    if (!t->rx_size) return IAP2_MORE;
    n = t->rx_size - t->rx_offset; if (n > capacity) n = capacity;
    memcpy(out, t->rx + t->rx_offset, n); mbedtls_platform_zeroize(t->rx + t->rx_offset, n); t->rx_offset += n; *size = n;
    if (t->rx_offset == t->rx_size) { t->rx_offset = t->rx_size = 0; t->again = 1; }
    return IAP2_OK;
}
void lockdown_tls_close(lockdown_tls *t) { if (live(t)) (void)stop(t, LOCKDOWN_TLS_REASON_LOCAL, LOCKDOWN_TLS_CLOSED); }
static uint32_t limit(uint32_t delay, uint64_t now, uint64_t at, uint32_t ms) {
    uint64_t elapsed = now - at; uint32_t left = elapsed >= ms ? 0 : ms - (uint32_t)elapsed; return delay < left ? delay : left;
}
uint32_t lockdown_tls_next_delay(const lockdown_tls *t) {
    enum usbmux_connection_state state; uint64_t now; uint32_t delay;
    if (!live(t)) return UINT32_MAX;
    if (usbmux_dispatcher_state(t->dispatcher, &t->handle, &state)) return 0;
    now = t->now > t->dispatcher->now ? t->now : t->dispatcher->now;
    delay = usbmux_dispatcher_next_delay(t->dispatcher); if (delay > 5) delay = 5;
    if (t->again) delay = 0;
    if (t->state == LOCKDOWN_TLS_HANDSHAKE) delay = limit(delay, now, t->started_at, t->config.handshake_ms);
    if (t->tx_size) delay = limit(delay, now, t->write_at, t->config.write_ms);
    if (t->rx_size) delay = limit(delay, now, t->held_at, t->config.hold_ms);
    return delay;
}
