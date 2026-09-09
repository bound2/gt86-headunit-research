/* SPDX-License-Identifier: GPL-3.0-only
 * Bounded projection-control framing. See reports/projection-control.md.
 * No socket, cipher, pairing, plist semantics or implicit success response.
 */
#ifndef GT86_RTSP_WIRE_H
#define GT86_RTSP_WIRE_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define RTSP_MAX_HEADER_SIZE 8192u
#define RTSP_MAX_BODY_SIZE 65536u
#define RTSP_MAX_MESSAGE_SIZE (RTSP_MAX_HEADER_SIZE + RTSP_MAX_BODY_SIZE)
#define RTSP_MAX_HEADERS 32u
#define RTSP_BUSY 3
enum rtsp_protocol { RTSP_10, RTSP_HTTP_10, RTSP_HTTP_11 };
enum rtsp_kind { RTSP_REQUEST, RTSP_RESPONSE };
typedef struct rtsp_slice { const uint8_t *data; size_t size; } rtsp_slice;
typedef struct rtsp_header { rtsp_slice name, value; } rtsp_header;
typedef struct rtsp_message {
    enum rtsp_kind kind;
    enum rtsp_protocol protocol;
    rtsp_slice method, target, reason, body;
    rtsp_header headers[RTSP_MAX_HEADERS];
    size_t header_count;
    uint32_t cseq;
    uint16_t status;
    uint8_t has_cseq;
} rtsp_message;
typedef struct rtsp_response {
    uint16_t status; /* Explicit 100..599. Channel replies require final >=200. */
    rtsp_slice reason; /* Empty selects a known standard phrase; unknown needs one. */
    const rtsp_header *headers;
    size_t header_count;
    rtsp_slice body;
} rtsp_response;
/* One message, exact consumption; MORE/errors zero result/consumed. Views borrow
 * input. Strict CRLF, ASCII text, token method/header names, exact supported
 * protocol, decimal Content-Length/CSeq only. RTSP requires CSeq; HTTP may omit
 * it. Body length defaults to zero. Duplicate CL/CSeq, Transfer-Encoding,
 * obs-fold and interleaved '$' packets reject. Unknown headers remain ordered;
 * repeated unknown names are preserved. Limits are local, not conformance.
 * No overlapping input/output objects, concurrent access or reentry anywhere.
 */
int rtsp_message_decode(const uint8_t *, size_t, rtsp_message *, size_t *consumed);
/* ASCII-insensitive name match. END if absent, INVALID if repeated. */
int rtsp_header_get(const rtsp_message *, rtsp_slice name, rtsp_slice *value);
/* Echo request protocol and numeric CSeq; always generate one Content-Length.
 * Extra headers cannot override CL/CSeq/TE; other names must be unique. Values
 * cannot inject CR/LF/control/high bytes. Fully validate/measure before writing;
 * failures leave output unchanged and written zero. out=NULL,capacity=0 is a
 * measurement-only call returning OK/required bytes. All buffers are disjoint;
 * response body may borrow request input, but must not overlap output.
 */
int rtsp_response_encode(const rtsp_message *, const rtsp_response *, uint8_t *out,
                         size_t capacity, size_t *written);
typedef struct rtsp_stream {
    uint8_t *buffer;
    size_t capacity, used, expected, header_size;
    int error;
    uint8_t complete;
} rtsp_stream;
/* Caller storage 64..RTSP_MAX_MESSAGE_SIZE. feed copies only the first message,
 * parses headers once to learn the body length and stops exactly at its end.
 * No rescanning partial bodies or following-message read-ahead. Input errors
 * are terminal until explicit clear/init; complete feed returns BUSY/count0.
 * message returns an immutable borrowed view until clear/init. clear zeroes
 * used bytes, including pairing bodies. No hidden clock/EOF/reconnect policy.
 */
int rtsp_stream_init(rtsp_stream *, uint8_t *, size_t capacity);
int rtsp_stream_feed(rtsp_stream *, const uint8_t *, size_t, size_t *consumed);
int rtsp_stream_message(const rtsp_stream *, rtsp_message *);
void rtsp_stream_clear(rtsp_stream *);
#ifdef __cplusplus
}
#endif
#endif
