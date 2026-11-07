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
 * feature member (the Aurora app): the lite member's node on threads of its
 * own, with the app's key through sign. event gets each event as JSON,
 * {"type":"write","text","kind","ttl_ms"}, {"type":"log","line"},
 * {"type":"identity","cert","issuer","roots"} or {"type":"mute","muted","for_ms","by"},
 * on any thread; ctx must stay valid for the rest of the process.
 * cbb_member_pause takes {"pause":true,"for_ms"} or {"pause":false}; it and
 * cbb_member_muted answer {"paused","paused_ms","muted","muted_ms"}.
 * cbb_member_devices answers {"devices":[{"device","name","role","os","admin",
 * "root","frozen","online","self","listed"}]}.
 */
typedef void (*cbb_event_fn)(void *ctx, const uint8_t *event, size_t len);

typedef struct cbb_member cbb_member;

cbb_member *cbb_member_start(const uint8_t *request, size_t len, cbb_sign_fn sign, cbb_event_fn event, void *ctx,
                             uint8_t **answer, size_t *answer_len);
uint8_t *cbb_member_copy(const cbb_member *m, const uint8_t *request, size_t len, size_t *answer_len);
uint8_t *cbb_member_peers(const cbb_member *m, size_t *answer_len);
uint8_t *cbb_member_devices(const cbb_member *m, size_t *answer_len);
uint8_t *cbb_member_pause(const cbb_member *m, const uint8_t *request, size_t len, size_t *answer_len);
uint8_t *cbb_member_muted(const cbb_member *m, size_t *answer_len);
void cbb_member_stop(cbb_member *m);

/*
 * The texts of the QR codes in a grey camera frame (src/qr.rs), only with the
 * feature join: height rows of width bytes, stride bytes apart; the answer is
 * {"texts":[...]}.
 */
uint8_t *cbb_qr_read(const uint8_t *gray, size_t width, size_t height, size_t stride, size_t *answer_len);

/*
 * Admitting a device by its QR code as an admin of the group (src/admit.rs),
 * only with the feature member: request is {"qr","public","admin_ca","make_admin"},
 * public the point of the key sign holds (the phone's admin key, or the root's
 * key with no admin_ca), and the answer {"addrs"} to dial. For each address,
 * cbb_admit_dial starts a connection and cbb_admit_feed takes what arrives;
 * both answer {"send","state","wrong_code","device","confirmed","error"}, state
 * pending, admitted (the device is in the group, its record sent; device is
 * {"device","name","os","role","admin"}), done or failed. m stays running
 * until cbb_admit_free.
 */
typedef struct cbb_admit cbb_admit;

cbb_admit *cbb_admit_new(const cbb_member *m, const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx,
                         uint8_t **answer, size_t *answer_len);
uint8_t *cbb_admit_dial(cbb_admit *a, size_t *answer_len);
uint8_t *cbb_admit_feed(cbb_admit *a, const uint8_t *data, size_t len, int64_t now_ms, size_t *answer_len);
void cbb_admit_free(cbb_admit *a);

#ifdef __cplusplus
}
#endif

#endif
