/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 HunterEwok */

/*
 * The Rust core's one entry point as C functions (docs/core-api.md), from
 * the library ffi/ builds (libcbb_ffi). A request and its answer are
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
 * A panic in any of these functions is caught and answered, code 5 "panic"
 * with what broke and where in details (docs/core-api.md, "Panics"). A
 * function that can answer only NULL leaves the answer to cbb_last_panic,
 * NULL when nothing panicked. cbb_test_panic panics on purpose and answers
 * it, for the wrappers' tests. Both answers go back with cbb_free.
 */
uint8_t *cbb_last_panic(size_t *answer_len);
uint8_t *cbb_test_panic(size_t *answer_len);

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
/*
 * Announces the joiner by mDNS while the app listens on port, so that a
 * computer of the group finds it by the code typed there; the announcement
 * ends with cbb_join_free. Returns 1 when it announced. Only in the build
 * with the member (the Aurora app's).
 */
int32_t cbb_join_announce(cbb_join *j, uint16_t port);
/*
 * With "invite" in the request, a remote invitation's text, the joiner
 * dials in place of listening (docs/protocol.md, section 12): it starts the
 * invitation's guest tunnel, the answer's "port" is the tunnel's loopback
 * port, which the app dials for each attempt, and cbb_join_accept's answer
 * has "send", the first bytes to send. cbb_join_answered returns 1 once the
 * invitation's hub answered through the tunnel. Only in the build with the
 * tunnel.
 */
int32_t cbb_join_answered(const cbb_join *j);
void cbb_join_free(cbb_join *j);

/*
 * The member inside the app (src/member.rs), only in a library built with the
 * feature member (the phones' apps): cbb's node on threads of its
 * own, with the app's key through sign. event gets each event as JSON on any
 * thread: {"type":"write","text","kind","ttl_ms"}, {"type":"log","line"},
 * {"type":"identity","cert","issuer","roots"}, {"type":"copy","copy"},
 * {"type":"message","from","message"}, {"type":"peer","peer"},
 * {"type":"tunnel","from","offer"}, {"type":"command","token","from",
 * "command"}, which the app answers with the op "answer", or
 * {"type":"mute","muted","for_ms","by"}; ctx must stay valid for the rest
 * of the process.
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
/*
 * The app's keys for the servers (docs/protocol.md, section 18), by name
 * ("server TAG" or "period TAG"): op 0 answers 0 when the app holds the key
 * name, 1 writes its public point (SEC1, 65 bytes) to out, making the key
 * first, 2 writes its signature (DER) of the 32-byte digest to out, 3 drops
 * every key but those name lists, one a line. out has room for 72 bytes and
 * out_len gets how many it holds; any answer but 0 is a failure. ctx must
 * stay valid, and the callback callable from any thread, for the rest of
 * the process.
 */
typedef int32_t (*cbb_keys_fn)(void *ctx, int32_t op, const uint8_t *name, size_t name_len, const uint8_t *digest,
                               uint8_t *out, size_t *out_len);
/*
 * Makes the member do what the service does for the servers: it keeps the
 * group's server credentials with its keys for them behind keys, signs its
 * server key and, on the root, the hubs' and members' credentials and the
 * period the app hands the root key for (cbb_member_manage, period); it may
 * then be one of the group's hubs (the ops hub, hub_off) or meet the group at
 * a blind relay (relay). The answer is {"ok"} or {"error"}.
 */
uint8_t *cbb_member_servers(const cbb_member *m, cbb_keys_fn keys, void *ctx, size_t *answer_len);
/*
 * Stops the member. It stays valid for the rest of the process: another
 * thread may still call it, and a call after the stop answers that the
 * member stopped; stopping it again does nothing.
 */
void cbb_member_stop(cbb_member *m);
/*
 * An admin's change to a device of the group or command for it, signed with
 * the key public names (the phone's admin key, or the root's key with no
 * admin_ca) through sign, called during this call only (src/member.rs,
 * manage): request is {"action","device","name","for_ms","allow_file_key",
 * "records","public","admin_ca","timeout_ms","method","kind","text","enter"},
 * action remove, rename, thaw, make_admin (the root, for a computer
 * connected), mute, unmute, sync_on, sync_off (the device's house, a mode
 * command), paste (method paste or type, kind text, secret or media: text is
 * then a copy_media copy's ID), paste_off, renew (every
 * member certificate due, and as the root every admin CA from an earlier root;
 * no device) or resolve (the root voids the records an alert of the member's
 * alerts op names); the answer {}, {"result"} for a command, or {"renewed":
 * count}. A command blocks on the network. Taking the group over
 * (src/takeover.rs): root_ca, public the new key, answers {"root_ca"}, which
 * the app keeps; take_over (device the lost root), take_handed_over or recover
 * (the recovery key) claims the group for "root_ca"; finish_takeover with
 * "root_ca", public its key, "name", "os", "store", "seal" answers
 * {"state","left_ms"} while the claim waits, signing nothing, and
 * {"state":"effective","cert"} once it made the phone the root.
 * recover_with_sheet with "sheet" (the recovery sheet's QR code) and
 * "root_ca" claims the group for a phone that restored it (cbb_restore): the
 * sheet's key signs the claim, sign is not called. period, on the root of a
 * member that serves the servers (cbb_member_servers), signs the next period
 * of the server credentials with the root key, when one is due, and answers
 * {"period_due"}.
 */
uint8_t *cbb_member_manage(const cbb_member *m, const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx,
                           size_t *answer_len);

/*
 * Restores a group on a new phone with its recovery key (src/restore.rs):
 * request is {"sheet","public","name","os","addrs","wait_ms"}, sheet the recovery
 * sheet's QR code and public the phone's member key point, which sign signs
 * with during this call only. It blocks while it browses for the group by
 * the sheet's tag (or asks addrs, "host:port") and takes the records from a member on a connection that
 * carries records only, checked; the answer {"device","cert","issuer",
 * "group_ca","roots","records","addr"} is what the app starts its member with.
 * In place of sheet, "card" is the keys cbb_piv's issue answers (the recovery
 * keys on a YubiKey): it then browses for any group and tries each.
 */
uint8_t *cbb_restore(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, size_t *answer_len);

/*
 * The app's YubiKey (src/piv.rs), only with the feature member: sends apdu
 * (len bytes) to the card and writes its answer, the status word last, to
 * out (at most out_cap bytes) and the length to out_len; returns 0, or
 * another value when the card left.
 */
typedef int32_t (*cbb_transmit_fn)(void *ctx, const uint8_t *apdu, size_t len, uint8_t *out, size_t out_cap,
                                   size_t *out_len);

/*
 * One step with the group's recovery key on a YubiKey (src/piv.rs): the core
 * speaks PIV and transmit carries each APDU, during this call only. request
 * is {"op",...}: "make" {"pin"} makes a key in a free retired slot and
 * answers {"slot","key"} (its SubjectPublicKeyInfo, for manage's
 * recovery_for); "put" {"slot","cert"} stores the admin CA; "issue"
 * {"pin","public"} has each recovery key on the card issue a member
 * certificate for public, {"keys":[{"slot","admin_ca","device","cert","public"}]}
 * (public the slot's key point);
 * "sign" {"pin","slot","public","digest"} answers {"sig"}, DER.
 */
uint8_t *cbb_piv(const uint8_t *request, size_t len, cbb_transmit_fn transmit, void *ctx, size_t *answer_len);

/*
 * Signs a manage request as cbb_member_manage does, with a slot's key on the
 * app's YubiKey (src/piv.rs), as the recovery key claims the group
 * (action recover): request adds "pin" and "slot" to manage's fields,
 * public the slot's key point, and transmit carries each APDU to the card
 * during this call only. When the card refused, the answer is its error.
 */
uint8_t *cbb_member_manage_card(const cbb_member *m, const uint8_t *request, size_t len, cbb_transmit_fn transmit,
                                void *ctx, size_t *answer_len);

/*
 * The texts of the QR codes in a grey camera frame (src/qr.rs), only with the
 * feature join: height rows of width bytes, stride bytes apart; the answer is
 * {"texts":[...]}.
 */
uint8_t *cbb_qr_read(const uint8_t *gray, size_t width, size_t height, size_t stride, size_t *answer_len);

/*
 * A group the phone makes, its root key the app's (src/join.rs, new_group),
 * only with the feature join: the request is
 * {"name","os","store":"hardware"|"file","root_public","public","seal"?}, the
 * keys' points base64, and sign the root key's callback, called during this
 * call only; the answer has a join's fields (device, cert, group_ca, roots,
 * records).
 */
uint8_t *cbb_group_new(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, size_t *answer_len);

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

/*
 * A remote invitation an admin phone makes (src/invite.rs): request is
 * {"public","admin_ca","expires","hub"} as for cbb_admit_new, expires in
 * seconds (an hour when 0, a day at most) and hub a device ID or empty for
 * any connected hub; sign with ctx signs until cbb_invite_free. The answer
 * is {"invite","expires","modules"}; it waits for the hub, so the app calls
 * it off its main thread. cbb_invite_next waits up to timeout_ms for a
 * state past version and answers {"version","state","joining","name",
 * "device","error"}, state open, joining (joining is
 * {"device","name","os","fingerprint"}: the app asks the user and answers
 * with cbb_invite_answer), done or failed. cbb_invite_free ends it and
 * waits for its window to close.
 */
typedef struct cbb_invite cbb_invite;

cbb_invite *cbb_invite_new(const cbb_member *m, const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx,
                           uint8_t **answer, size_t *answer_len);
uint8_t *cbb_invite_next(const cbb_invite *i, uint64_t version, uint64_t timeout_ms, size_t *answer_len);
void cbb_invite_answer(const cbb_invite *i, int32_t yes);
void cbb_invite_free(cbb_invite *i);

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

/*
 * Makes a relay link of cbb_tunnel_relay register with the group's server
 * credentials, signed with the period's server key through sign and ctx,
 * which stay valid until the link stops or is given other credentials; an
 * empty "credentials" goes back to the member certificate. The answer is as
 * cbb_tunnel's.
 */
uint8_t *cbb_tunnel_relay_credentials(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx,
                                      size_t *answer_len);

#ifdef __cplusplus
}
#endif

#endif
