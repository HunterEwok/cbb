/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 HunterEwok */

/*
 * The Rust core's one entry point as C functions (docs/core-api.md), from
 * the library lite/ffi builds (libcbb_ffi). A request and its answer are
 * JSON bytes; the answer is the caller's until it gives it back with
 * cbb_free. The functions never fail: a refusal is an answer with an error
 * code. They keep no state between calls and may be called from any
 * thread.
 */
#ifndef CBB_CORE_H
#define CBB_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The version of the request and answer shapes the library speaks. */
uint32_t cbb_abi(void);

/*
 * Answers the len bytes at request (NULL with len 0 is an empty request),
 * writing the answer's length to answer_len. Returns NULL only when
 * answer_len is NULL or request is NULL with a length.
 */
uint8_t *cbb_call(const uint8_t *request, size_t len, size_t *answer_len);

/* Gives back an answer of cbb_call with the length it wrote; NULL does nothing. */
void cbb_free(uint8_t *answer, size_t len);

/*
 * Joining a group by the phone's QR code with a key the core does not hold
 * (src/join.rs), only in a library built with the feature join (the Aurora
 * app). The answers are JSON as cbb_call's, given back with cbb_free; the
 * app does the sockets and passes each connection's bytes.
 */

/*
 * Signs the 32-byte SHA-256 digest at digest with the device key: writes an
 * ECDSA P-256 signature, DER, to sig (72 bytes of room) and its length to
 * sig_len. Returns 0 when it signed.
 */
typedef int32_t (*cbb_sign_fn)(void *ctx, const uint8_t *digest, uint8_t *sig, size_t *sig_len);

typedef struct cbb_join cbb_join;

cbb_join *cbb_join_new(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, uint8_t **answer,
                       size_t *answer_len);
/*
 * As cbb_join_new, for a phone that asks to be an admin: the request names
 * "admin_public", the admin key's public point, and admin_sign with
 * admin_ctx signs with that key. The joined answer carries "admin_ca" when
 * the member made the phone an admin.
 */
cbb_join *cbb_join_new_admin(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, cbb_sign_fn admin_sign,
                             void *admin_ctx, uint8_t **answer, size_t *answer_len);
uint8_t *cbb_join_accept(cbb_join *j, size_t *answer_len);
uint8_t *cbb_join_feed(cbb_join *j, const uint8_t *data, size_t len, int64_t now_ms, size_t *answer_len);
uint8_t *cbb_join_finish(cbb_join *j, int32_t saved, size_t *answer_len);
void cbb_join_free(cbb_join *j);

/*
 * The member inside the app (src/member.rs), only in a library built with the
 * feature member (the phones' apps): the lite member's node on threads of its
 * own, with the app's key through sign. event gets each event as JSON on any
 * thread: {"type":"write","text","kind","ttl_ms"}, {"type":"log","line"},
 * {"type":"identity","cert","issuer","roots"}, {"type":"copy","copy"},
 * {"type":"message","from","message"} or {"type":"mute","muted","for_ms","by"};
 * ctx must stay valid for the rest of the process.
 */
typedef void (*cbb_event_fn)(void *ctx, const uint8_t *event, size_t len);

typedef struct cbb_member cbb_member;

cbb_member *cbb_member_start(const uint8_t *request, size_t len, cbb_sign_fn sign, cbb_event_fn event, void *ctx,
                             uint8_t **answer, size_t *answer_len);
/*
 * Asks the member: request is {"op","args"} (docs/core-api.md, "The
 * member"), the answer {"ok"} or {"error"}, given back with cbb_free. fetch,
 * command and wait block on the network: call them off the main thread.
 */
uint8_t *cbb_member_call(const cbb_member *m, const uint8_t *request, size_t len, size_t *answer_len);
void cbb_member_stop(cbb_member *m);

/*
 * The phones' tunnel to the hub (src/tunnel.rs), only in a library built with
 * the feature tunnel (the iPhone and Android apps): request is JSON with its
 * "op" (new_key, public_key, start, status, stop, and hub_... for the phone
 * as the group's hub); the answer, given back with cbb_free, is
 * {"ok": ...} or {"error": {...}}. A started tunnel's loopback port leads
 * to the hub's member port.
 */
uint8_t *cbb_tunnel(const uint8_t *request, size_t len, size_t *answer_len);

/*
 * Registers a hub of cbb_tunnel with the group's forwarder, its TLS signed
 * with the member key through sign and ctx, which stay valid until the hub
 * stops or registers again; the answer is as cbb_tunnel's.
 */
uint8_t *cbb_tunnel_register(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, size_t *answer_len);

/*
 * Links the phone to the group's blind relay, its TLS signed with the member
 * key through sign, its events (dial, calling, changed, log) given to event,
 * both with ctx, which stay valid until relay_stop returns; the answer is
 * as cbb_tunnel's, with the link's "id".
 */
uint8_t *cbb_tunnel_relay(const uint8_t *request, size_t len, cbb_sign_fn sign, cbb_event_fn event, void *ctx,
                          size_t *answer_len);

#ifdef __cplusplus
}
#endif

#endif
