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
 * Signs the 32-byte SHA-256 digest at digest with the device key: writes an
 * ECDSA P-256 signature, DER, to sig (72 bytes of room) and its length to
 * sig_len. Returns 0 when it signed.
 */
typedef int32_t (*cbb_sign_fn)(void *ctx, const uint8_t *digest, uint8_t *sig, size_t *sig_len);

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
 * "records","text","mode","kind","enter","public","admin_ca","timeout_ms"},
 * action remove, rename, thaw, make_admin (the root, for a computer
 * connected), mute, unmute, sync_on, sync_off (the device's house, a mode
 * command), paste ("text" put where the device's focus is, "mode" paste or
 * type, "kind" text, secret or media, the last with "text" the event ID of
 * a copy of images or files the phone made just before), paste_off,
 * actions_off, away_off, action (name the quick action), freeze (an admin
 * that removes no admins), renew (every
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
 * period, on the root of a
 * member that serves the servers (cbb_member_servers), signs the next period
 * of the server credentials with the root key, when one is due, and answers
 * {"period_due"}. add_watch, the root with "key" (the watch's admin key's
 * SubjectPublicKeyInfo), "name", "os" and an optional "device", makes a watch
 * an admin and answers {"device","admin_ca","group","signer"} for the watch;
 * watch_actions (nothing signed) answers {"actions"}, what a watch may do to
 * device: freeze, remove, paste-off, actions-off, away-off, action.
 */
uint8_t *cbb_member_manage(const cbb_member *m, const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx,
                           size_t *answer_len);

/*
 * The app's YubiKey (src/piv.rs), only with the feature member. With the
 * transport "apdu": sends apdu (len bytes) to the card and writes its
 * answer, the status word last, to out (at most out_cap bytes) and the
 * length to out_len. With "ccid_bulk" (a YubiKey's CCID interface on USB):
 * len > 0 writes those bytes to the bulk-out endpoint, out_len 0; len 0
 * reads one bulk-in transfer into out, out_len 0 when nothing came within
 * about a second. Returns 0, or another value when the card left.
 */
typedef int32_t (*cbb_transmit_fn)(void *ctx, const uint8_t *apdu, size_t len, uint8_t *out, size_t out_cap,
                                   size_t *out_len);

/*
 * One step with the group's recovery key on a YubiKey (src/piv.rs; docs/protocol.md,
 * "The recovery key on a YubiKey (0.6)"): the core speaks PIV and transmit
 * carries each APDU, during this call only. request is {"op",...}: "inspect"
 * {"pin"} answers {"default_key"}; "seal" {"pin","recovery","replace_default",
 * "management"} seals the sheet's secret (recovery as manage's change_root
 * takes it) and answers {"default_key","replaced","warning"}; "open" {"pin"}
 * answers {"secret"}, base64, for change_root's recovery. "transport" is
 * "apdu" (the default) or "ccid_bulk", as cbb_transmit_fn says, or "pcsc"
 * on a system that runs pcscd (Aurora OS): the core is the PC/SC client
 * and never calls transmit, which must still be a function; open takes the
 * one card with cbb's key, inspect and seal the one card that has PIV.
 */
uint8_t *cbb_piv(const uint8_t *request, size_t len, cbb_transmit_fn transmit, void *ctx, size_t *answer_len);

/*
 * The app's link to its watch (src/watch.rs), only with the feature member:
 * sends body (len bytes), a record or command the watch is shown whole, to
 * the watch and writes its ECDSA P-256 signature over the body's SHA-256,
 * DER, to sig (72 bytes of room) and the length to sig_len; returns 0, or
 * another value when the watch refused or went away.
 */
typedef int32_t (*cbb_sign_body_fn)(void *ctx, const uint8_t *body, size_t len, uint8_t *sig, size_t *sig_len);

/*
 * Does what the app's watch asked from the wrist, signed by the watch's admin
 * key through sign_body during this call only: request is {"action","device",
 * "watch","public","admin_ca","name","timeout_ms"}, action one of
 * watch_actions for device (freeze, remove, paste_off, actions_off, away_off,
 * action), watch the watch's device ID, public its key point and admin_ca
 * what add_watch made. The answer is as cbb_member_manage's.
 */
uint8_t *cbb_member_manage_watch(const cbb_member *m, const uint8_t *request, size_t len, cbb_sign_body_fn sign_body,
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
 * records). On 0.6 the request also names "dir" (src/found.rs; no "seal"):
 * the set is kept there for cbb_member_start, and the answer is
 * {"group","device","recovery":{"qr","text":[4 lines],"modules"}}, the recovery sheet,
 * which the core keeps nowhere.
 */
uint8_t *cbb_group_new(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, size_t *answer_len);

/*
 * A remote invitation an admin phone makes (src/invite.rs): request is
 * {"public","admin_ca","expires","hub","kind"}, public the point of the key
 * sign holds (the phone's admin key, or the root's key with no admin_ca; a
 * member of 0.6 needs no admin_ca), expires in seconds (an hour when 0, a
 * day at most), hub a device ID or empty for any connected hub, and kind
 * the device invited on 0.6, "computer" (or empty) or "phone"; sign with
 * ctx signs until cbb_invite_free. The answer is {"invite","expires",
 * "modules"}; it waits for the hub, so the app calls it off its main
 * thread. cbb_invite_next waits up to timeout_ms for a
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
 * A home window on a member of 0.6 (src/window.rs): an admin phone, or the
 * root phone, lets a device join at home by six digits. The member port
 * must listen (the member's "listen"). request is
 * {"public","addrs","expires","mdns"}: the admitting key (admin or root),
 * which sign with ctx signs with until cbb_window_free; the phone's home
 * addresses without a port; seconds open (five minutes when 0, an hour at
 * most); mdns to have the core announce it (Aurora; the other apps announce
 * p=1, f and i with the system's DNS-SD). The answer is
 * {"qr","digits","id","fingerprint","expires","modules"}: qr a
 * cbb://pair link with the addresses, the phone's key hash, the window's ID
 * and its digits; digits the six to show for a device that types them. The
 * new device dials and proves the digits; nobody is asked. cbb_window_next
 * waits up to timeout_ms for a state past version and answers
 * {"version","state","name","device","error"}, state open, joining (a
 * device pairs), done (a device joined: device, name; the window is
 * closed), failed (that attempt failed; the window stays open) or closed
 * (its time is up, or three wrong codes: error). cbb_window_free closes it.
 */
typedef struct cbb_window cbb_window;
cbb_window *cbb_window_new(const cbb_member *m, const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx,
                           uint8_t **answer, size_t *answer_len);
uint8_t *cbb_window_next(const cbb_window *w, uint64_t version, uint64_t timeout_ms, size_t *answer_len);
void cbb_window_free(cbb_window *w);

/*
 * A new phone joins a group of 0.6 by a home window (src/joiner.rs):
 * request is {"dir","qr","digits","name","os","public"}: qr the window's QR
 * code text, or empty with digits the six the person typed (the core then
 * finds the one window announced by mDNS); public the member key, which
 * sign with ctx signs with until cbb_joiner_free. It dials the window's
 * addresses on a thread of its own, takes only the member whose key the
 * window names and proves the digits. The answer is the first state;
 * cbb_joiner_next waits up to timeout_ms for a state past version and
 * answers {"version","state","group","device","name","error"}, state
 * dialing, done (the set is kept in dir: start the member on it; name is
 * the member that let it in) or failed. cbb_joiner_free ends it.
 * cbb_joiner_new_admin also offers the admin key the request names in
 * admin_public, admin_sign with admin_ctx signing its proof over the
 * session: the group's root keeps it and makes the phone an admin later.
 */
typedef struct cbb_joiner cbb_joiner;
cbb_joiner *cbb_joiner_new(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, uint8_t **answer,
                           size_t *answer_len);
cbb_joiner *cbb_joiner_new_admin(const uint8_t *request, size_t len, cbb_sign_fn sign, void *ctx, cbb_sign_fn admin_sign,
                                 void *admin_ctx, uint8_t **answer, size_t *answer_len);
uint8_t *cbb_joiner_next(const cbb_joiner *j, uint64_t version, uint64_t timeout_ms, size_t *answer_len);
void cbb_joiner_free(cbb_joiner *j);

#ifdef __cplusplus
}
#endif

#endif
