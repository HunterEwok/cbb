// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// libcbb_napi.so: the Rust core's C functions (ffi/include/cbb_core.h,
// docs/core-api.md) for the app's ArkTS, one function each, and the keys in
// HUKS (keys.h). Requests and answers are the core's JSON as strings, bytes
// on the wire as ArrayBuffers. Every function that may block, or that hands
// the core a key that signs, runs on a worker thread and answers a Promise:
// the admin key waits there for the user's face or fingerprint, which the
// app asks for on its main thread (setAuth), so nothing that signs may run
// on that thread. The handles (a member, a joiner, an admission, an
// invitation) are opaque objects the app gives back to free them.

#include "keys.h"

#include <cbb_core.h>

#include <napi/native_api.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {

// ---- values between ArkTS and C++ ----

std::string stringOf(napi_env env, napi_value v)
{
    size_t len = 0;
    if (napi_get_value_string_utf8(env, v, nullptr, 0, &len) != napi_ok)
        return std::string();
    std::string s(len, '\0');
    napi_get_value_string_utf8(env, v, s.data(), len + 1, &len);
    return s;
}

std::vector<uint8_t> bytesOf(napi_env env, napi_value v)
{
    void *data = nullptr;
    size_t len = 0;
    if (napi_get_arraybuffer_info(env, v, &data, &len) != napi_ok || !data)
        return {};
    const auto *p = static_cast<const uint8_t *>(data);
    return std::vector<uint8_t>(p, p + len);
}

int64_t intOf(napi_env env, napi_value v)
{
    int64_t n = 0;
    napi_get_value_int64(env, v, &n);
    return n;
}

bool boolOf(napi_env env, napi_value v)
{
    bool b = false;
    napi_get_value_bool(env, v, &b);
    return b;
}

napi_value str(napi_env env, const std::string &s)
{
    napi_value v = nullptr;
    napi_create_string_utf8(env, s.data(), s.size(), &v);
    return v;
}

napi_value num(napi_env env, double n)
{
    napi_value v = nullptr;
    napi_create_double(env, n, &v);
    return v;
}

napi_value boolean(napi_env env, bool b)
{
    napi_value v = nullptr;
    napi_get_boolean(env, b, &v);
    return v;
}

napi_value buffer(napi_env env, const std::vector<uint8_t> &b)
{
    void *data = nullptr;
    napi_value v = nullptr;
    napi_create_arraybuffer(env, b.size(), &data, &v);
    if (!b.empty())
        std::memcpy(data, b.data(), b.size());
    return v;
}

napi_value undefined(napi_env env)
{
    napi_value v = nullptr;
    napi_get_undefined(env, &v);
    return v;
}

// The arguments of a call, at most eight.
struct Args {
    napi_value v[8] = {};
    size_t n = 8;
    Args(napi_env env, napi_callback_info info) { napi_get_cb_info(env, info, &n, v, nullptr, nullptr); }
};

// An answer of the core as a string, given back to it.
std::string take(uint8_t *answer, size_t len)
{
    if (!answer)
        return std::string();
    std::string s(reinterpret_cast<const char *>(answer), len);
    cbb_free(answer, len);
    return s;
}

// The core's error answer for a failure here, in its shape, so that the
// app reads every failure the same way.
std::string errorAnswer(const keys::Failure &f)
{
    auto quote = [](const std::string &s) {
        std::string out = "\"";
        for (const char c : s) {
            if (c == '"' || c == '\\') {
                out += '\\';
                out += c;
            } else if (c == '\n') {
                out += "\\n";
            } else if (static_cast<unsigned char>(c) < 0x20) {
                out += ' ';
            } else {
                out += c;
            }
        }
        return out + "\"";
    };
    return "{\"error\":{\"code\":0,\"name\":\"app\",\"message\":" + quote(f.message) + ",\"details\":" + quote(f.details) + "}}";
}

keys::Which whichOf(napi_env env, napi_value v)
{
    return stringOf(env, v) == "admin" ? keys::Which::Admin : keys::Which::Member;
}

cbb_sign_fn signerOf(keys::Which which)
{
    return which == keys::Which::Admin ? keys::signAdmin : keys::signMember;
}

// ---- work off the main thread ----

// A Promise settled by work on a worker thread: exec runs there, done on
// the main thread with its result.
struct Work {
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    std::function<void()> exec;
    std::function<napi_value(napi_env)> done;
};

napi_value later(napi_env env, std::function<void()> exec, std::function<napi_value(napi_env)> done)
{
    auto *w = new Work{nullptr, nullptr, std::move(exec), std::move(done)};
    napi_value promise = nullptr;
    napi_create_promise(env, &w->deferred, &promise);
    napi_value name = str(env, "cbb");
    napi_create_async_work(
        env, nullptr, name, [](napi_env, void *data) { static_cast<Work *>(data)->exec(); },
        [](napi_env env, napi_status, void *data) {
            auto *w = static_cast<Work *>(data);
            napi_resolve_deferred(env, w->deferred, w->done(env));
            napi_delete_async_work(env, w->work);
            delete w;
        },
        w, &w->work);
    napi_queue_async_work(env, w->work);
    return promise;
}

// A string answer computed off the main thread.
napi_value laterString(napi_env env, std::function<std::string()> exec)
{
    auto out = std::make_shared<std::string>();
    return later(env, [out, exec = std::move(exec)]() { *out = exec(); }, [out](napi_env env) { return str(env, *out); });
}

// ---- handles ----

napi_value handle(napi_env env, void *p)
{
    napi_value v = nullptr;
    napi_create_external(env, p, nullptr, nullptr, &v);
    return v;
}

template <typename T> T *handleOf(napi_env env, napi_value v)
{
    void *p = nullptr;
    if (napi_get_value_external(env, v, &p) != napi_ok)
        return nullptr;
    return static_cast<T *>(p);
}

// A handle made with an answer: {handle, answer}; handle is null when the
// core refused, and answer then says why.
napi_value made(napi_env env, void *p, const std::string &answer)
{
    napi_value o = nullptr;
    napi_create_object(env, &o);
    napi_value h = nullptr;
    if (p)
        h = handle(env, p);
    else
        napi_get_null(env, &h);
    napi_set_named_property(env, o, "handle", h);
    napi_set_named_property(env, o, "answer", str(env, answer));
    return o;
}

// ---- events from the core's threads ----

// A callback of the app's that the core's threads call with JSON: the
// member's events, a relay link's. The core may call it after the member
// stopped (cbb_member_stop), so it lives for the rest of the process, and
// a closed one drops what comes.
struct Events {
    napi_threadsafe_function fn = nullptr;
    std::atomic<bool> open{true};
};

void callEvent(napi_env env, napi_value js, void *, void *data)
{
    auto *line = static_cast<std::string *>(data);
    if (env && js) {
        napi_value arg = str(env, *line);
        napi_call_function(env, undefined(env), js, 1, &arg, nullptr);
    }
    delete line;
}

Events *eventsOf(napi_env env, napi_value js)
{
    auto *e = new Events;
    napi_value name = str(env, "cbb-events");
    napi_create_threadsafe_function(env, js, nullptr, name, 0, 1, nullptr, nullptr, nullptr, callEvent, &e->fn);
    // The app may end while the core still holds it.
    napi_unref_threadsafe_function(env, e->fn);
    return e;
}

void onEvent(void *ctx, const uint8_t *event, size_t len)
{
    auto *e = static_cast<Events *>(ctx);
    if (!e || !e->open.load())
        return;
    auto *line = new std::string(reinterpret_cast<const char *>(event), len);
    if (napi_call_threadsafe_function(e->fn, line, napi_tsfn_nonblocking) != napi_ok)
        delete line;
}

// ---- the user's face or fingerprint for the admin key ----

// The app's function that takes HUKS's challenge and answers a Promise of
// the auth token (an ArrayBuffer), set by setAuth.
napi_threadsafe_function authFn = nullptr;

// A question to one of the app's functions that take bytes and answer a
// Promise of bytes: HUKS's challenge to the auth token, or an APDU to the
// YubiKey's answer (setCard).
struct AuthAsk {
    std::vector<uint8_t> challenge;
    std::promise<std::vector<uint8_t>> token;
    std::string why;
    std::string what = "auth";
};

napi_value authSettled(napi_env env, napi_callback_info info, bool ok)
{
    size_t n = 1;
    napi_value v = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &n, &v, nullptr, &data);
    auto *ask = static_cast<AuthAsk *>(data);
    if (ok && n == 1) {
        ask->token.set_value(bytesOf(env, v));
    } else {
        if (n == 1) {
            napi_value s = nullptr;
            if (napi_coerce_to_string(env, v, &s) == napi_ok)
                ask->why = stringOf(env, s);
        }
        ask->token.set_value({});
    }
    return undefined(env);
}

void callAuth(napi_env env, napi_value js, void *, void *data)
{
    auto *ask = static_cast<AuthAsk *>(data);
    if (!env || !js) {
        ask->why = ask->what + ": the app is gone";
        ask->token.set_value({});
        return;
    }
    napi_value arg = buffer(env, ask->challenge);
    napi_value promise = nullptr;
    if (napi_call_function(env, undefined(env), js, 1, &arg, &promise) != napi_ok) {
        ask->why = ask->what + ": the app's function threw";
        ask->token.set_value({});
        return;
    }
    napi_value then = nullptr;
    napi_value resolved = nullptr;
    napi_value rejected = nullptr;
    napi_get_named_property(env, promise, "then", &then);
    napi_create_function(
        env, "resolved", NAPI_AUTO_LENGTH, [](napi_env env, napi_callback_info info) { return authSettled(env, info, true); }, ask,
        &resolved);
    napi_create_function(
        env, "rejected", NAPI_AUTO_LENGTH, [](napi_env env, napi_callback_info info) { return authSettled(env, info, false); }, ask,
        &rejected);
    napi_value args[2] = {resolved, rejected};
    if (napi_call_function(env, promise, then, 2, args, nullptr) != napi_ok) {
        ask->why = ask->what + ": the app's function did not answer a Promise";
        ask->token.set_value({});
    }
}

// How long the user has to answer the face or fingerprint prompt.
constexpr std::chrono::seconds authTimeout = std::chrono::minutes(3);

// Asks the app's function fn on its main thread and waits for its answer,
// at most timeout.
std::vector<uint8_t> askApp(napi_threadsafe_function fn, const std::vector<uint8_t> &challenge, const std::string &what,
                            std::chrono::seconds timeout, std::string *why)
{
    // The app's main thread answers through the Promise; ask stays alive
    // until it did or the wait ended, and a late answer is then dropped by
    // keeping ask for the rest of the process.
    auto *ask = new AuthAsk;
    ask->challenge = challenge;
    ask->what = what;
    std::future<std::vector<uint8_t>> token = ask->token.get_future();
    if (napi_call_threadsafe_function(fn, ask, napi_tsfn_blocking) != napi_ok) {
        delete ask;
        *why = what + ": could not reach the app's main thread";
        return {};
    }
    if (token.wait_for(timeout) != std::future_status::ready) {
        *why = what + ": no answer in time";
        return {};
    }
    std::vector<uint8_t> out = token.get();
    *why = ask->why;
    delete ask;
    return out;
}

std::vector<uint8_t> askAuth(const std::vector<uint8_t> &challenge, std::string *why)
{
    if (!authFn) {
        *why = "auth: the app set no function for the user's consent";
        return {};
    }
    return askApp(authFn, challenge, "auth", authTimeout, why);
}

// ---- the YubiKey over NFC ----

// The app's function that sends an APDU to the YubiKey on its IsoDep tag
// and answers a Promise of the card's answer, its status word last (setCard).
napi_threadsafe_function cardFn = nullptr;

// How long one APDU may take, a signature with the user's touch included.
constexpr auto cardTimeout = std::chrono::seconds(30);

// The core's cbb_transmit_fn over the app's function; ctx is ignored.
int32_t transmitCard(void *, const uint8_t *apdu, size_t len, uint8_t *out, size_t cap, size_t *outLen)
{
    if (!cardFn)
        return 2;
    std::string why;
    const std::vector<uint8_t> a = askApp(cardFn, std::vector<uint8_t>(apdu, apdu + len), "card", cardTimeout, &why);
    if (a.size() < 2 || a.size() > cap)
        return 1;
    std::memcpy(out, a.data(), a.size());
    *outLen = a.size();
    return 0;
}

// ---- the watch as an admin ----

// The app's function that sends a record or command to the watch, which
// shows it and signs it with its admin key, and answers a Promise of the
// signature, DER (setWatch).
napi_threadsafe_function watchFn = nullptr;

// How long the watch's wearer has to look at what it signs and confirm.
constexpr auto watchTimeout = std::chrono::minutes(2);

// The core's cbb_sign_body_fn over the app's function; ctx is ignored.
int32_t signOnWatch(void *, const uint8_t *body, size_t len, uint8_t *sig, size_t *sigLen)
{
    if (!watchFn)
        return 2;
    std::string why;
    const std::vector<uint8_t> s = askApp(watchFn, std::vector<uint8_t>(body, body + len), "watch", watchTimeout, &why);
    if (s.empty() || s.size() > 72)
        return 1;
    std::memcpy(sig, s.data(), s.size());
    *sigLen = s.size();
    return 0;
}

// ---- the core ----

napi_value abi(napi_env env, napi_callback_info)
{
    return num(env, cbb_abi());
}

// call(request: string): string, cbb_call: no keys, no network, quick.
napi_value call(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    size_t len = 0;
    return str(env, take(cbb_call(reinterpret_cast<const uint8_t *>(req.data()), req.size(), &len), len));
}

// setAuth(fn: (challenge: ArrayBuffer) => Promise<ArrayBuffer>): void
napi_value setAuth(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    if (authFn)
        napi_release_threadsafe_function(authFn, napi_tsfn_release);
    napi_value name = str(env, "cbb-auth");
    napi_create_threadsafe_function(env, a.v[0], nullptr, name, 0, 1, nullptr, nullptr, nullptr, callAuth, &authFn);
    napi_unref_threadsafe_function(env, authFn);
    keys::setAuth(askAuth);
    return undefined(env);
}

// keyEnsure(which: 'member' | 'admin'): Promise<string>, {"ok":{"public","created"}}
// with the point base64, or the core's error shape.
napi_value keyEnsure(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const keys::Which which = whichOf(env, a.v[0]);
    return laterString(env, [which]() {
        keys::Key key;
        keys::Failure f;
        if (!keys::ensure(which, &key, &f))
            return errorAnswer(f);
        static const char abc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string b64;
        const auto &p = key.point;
        for (size_t i = 0; i < p.size(); i += 3) {
            const uint32_t n = uint32_t(p[i]) << 16 | (i + 1 < p.size() ? uint32_t(p[i + 1]) << 8 : 0) | (i + 2 < p.size() ? p[i + 2] : 0);
            b64 += abc[n >> 18 & 63];
            b64 += abc[n >> 12 & 63];
            b64 += i + 1 < p.size() ? abc[n >> 6 & 63] : '=';
            b64 += i + 2 < p.size() ? abc[n & 63] : '=';
        }
        return std::string("{\"ok\":{\"public\":\"") + b64 + "\",\"created\":" + (key.created ? "true" : "false") + "}}";
    });
}

// keyForget(): Promise<string>, {"ok":{}} or an error.
napi_value keyForget(napi_env env, napi_callback_info)
{
    return laterString(env, []() {
        keys::Failure f;
        return keys::forget(&f) ? std::string("{\"ok\":{}}") : errorAnswer(f);
    });
}

// groupNew(request: string): Promise<string>, signed with the admin key.
napi_value groupNew(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    return laterString(env, [req]() {
        size_t len = 0;
        return take(cbb_group_new(reinterpret_cast<const uint8_t *>(req.data()), req.size(), keys::signAdmin, nullptr, &len), len);
    });
}

// restore(request: string): Promise<string>, signed with the member key.
napi_value restore(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    return laterString(env, [req]() {
        size_t len = 0;
        return take(cbb_restore(reinterpret_cast<const uint8_t *>(req.data()), req.size(), keys::signMember, nullptr, &len), len);
    });
}

// setCard(fn: (apdu: ArrayBuffer) => Promise<ArrayBuffer>): void, the
// YubiKey that piv and memberManageCard speak to.
napi_value setCard(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    if (cardFn)
        napi_release_threadsafe_function(cardFn, napi_tsfn_release);
    napi_value name = str(env, "cbb-card");
    napi_create_threadsafe_function(env, a.v[0], nullptr, name, 0, 1, nullptr, nullptr, nullptr, callAuth, &cardFn);
    napi_unref_threadsafe_function(env, cardFn);
    return undefined(env);
}

// setWatch(fn: (body: ArrayBuffer) => Promise<ArrayBuffer>): void, the
// watch that memberManageWatch has sign.
napi_value setWatch(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    if (watchFn)
        napi_release_threadsafe_function(watchFn, napi_tsfn_release);
    napi_value name = str(env, "cbb-watch");
    napi_create_threadsafe_function(env, a.v[0], nullptr, name, 0, 1, nullptr, nullptr, nullptr, callAuth, &watchFn);
    napi_unref_threadsafe_function(env, watchFn);
    return undefined(env);
}

// piv(request: string): Promise<string>, cbb_piv on the app's YubiKey.
napi_value piv(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    return laterString(env, [req]() {
        size_t len = 0;
        return take(cbb_piv(reinterpret_cast<const uint8_t *>(req.data()), req.size(), transmitCard, nullptr, &len), len);
    });
}

// qrRead(gray: ArrayBuffer, width, height, stride): string
napi_value qrRead(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::vector<uint8_t> gray = bytesOf(env, a.v[0]);
    const auto width = size_t(intOf(env, a.v[1]));
    const auto height = size_t(intOf(env, a.v[2]));
    const auto stride = size_t(intOf(env, a.v[3]));
    if (gray.size() < stride * height || width > stride)
        return str(env, errorAnswer({"", "qr: the frame is smaller than its size"}));
    size_t len = 0;
    return str(env, take(cbb_qr_read(gray.data(), width, height, stride, &len), len));
}

// ---- the member ----

struct Member {
    cbb_member *m = nullptr;
    Events *events = nullptr;
};

// memberStart(request: string, onEvent: (json: string) => void): Promise<{handle, answer}>
napi_value memberStart(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    auto *member = new Member;
    member->events = eventsOf(env, a.v[1]);
    auto answer = std::make_shared<std::string>();
    return later(
        env,
        [req, member, answer]() {
            uint8_t *out = nullptr;
            size_t len = 0;
            member->m = cbb_member_start(reinterpret_cast<const uint8_t *>(req.data()), req.size(), keys::signMember, onEvent,
                                         member->events, &out, &len);
            *answer = take(out, len);
        },
        [member, answer](napi_env env) {
            if (!member->m) {
                member->events->open.store(false);
                delete member; // its events stay, as the core may hold them
                return made(env, nullptr, *answer);
            }
            return made(env, member, *answer);
        });
}

// memberCall(handle, request: string): Promise<string>; fetch, command and
// wait block on the network.
napi_value memberCall(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    const std::string req = stringOf(env, a.v[1]);
    return laterString(env, [member, req]() {
        if (!member)
            return errorAnswer({"", "member: no handle"});
        size_t len = 0;
        return take(cbb_member_call(member->m, reinterpret_cast<const uint8_t *>(req.data()), req.size(), &len), len);
    });
}

// memberManage(handle, request: string, which): Promise<string>
napi_value memberManage(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    const std::string req = stringOf(env, a.v[1]);
    const cbb_sign_fn sign = signerOf(whichOf(env, a.v[2]));
    return laterString(env, [member, req, sign]() {
        if (!member)
            return errorAnswer({"", "member: no handle"});
        size_t len = 0;
        return take(cbb_member_manage(member->m, reinterpret_cast<const uint8_t *>(req.data()), req.size(), sign, nullptr, &len), len);
    });
}

// memberManageCard(handle, request: string): Promise<string>, signed with
// a slot's key on the app's YubiKey (cbb_member_manage_card).
napi_value memberManageCard(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    const std::string req = stringOf(env, a.v[1]);
    return laterString(env, [member, req]() {
        if (!member)
            return errorAnswer({"", "member: no handle"});
        size_t len = 0;
        return take(cbb_member_manage_card(member->m, reinterpret_cast<const uint8_t *>(req.data()), req.size(), transmitCard, nullptr, &len),
                    len);
    });
}

// memberManageWatch(handle, request: string): Promise<string>, what the
// watch asked from the wrist, signed on the watch (cbb_member_manage_watch).
napi_value memberManageWatch(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    const std::string req = stringOf(env, a.v[1]);
    return laterString(env, [member, req]() {
        if (!member)
            return errorAnswer({"", "member: no handle"});
        size_t len = 0;
        return take(cbb_member_manage_watch(member->m, reinterpret_cast<const uint8_t *>(req.data()), req.size(), signOnWatch, nullptr, &len),
                    len);
    });
}

// memberServers(handle, index: string): Promise<string>: the member keeps
// the group's server credentials and may be a hub or meet the group at a
// relay, with its keys for the servers in HUKS, listed in the file index.
napi_value memberServers(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    const std::string index = stringOf(env, a.v[1]);
    return laterString(env, [member, index]() {
        if (!member)
            return errorAnswer({"", "member: no handle"});
        keys::setServerIndex(index);
        size_t len = 0;
        return take(cbb_member_servers(member->m, keys::serverKeys, nullptr, &len), len);
    });
}

// memberStop(handle): Promise<void>. The member stays valid for the rest of
// the process (cbb_member_stop), so the handle is not freed.
napi_value memberStop(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    return later(
        env,
        [member]() {
            if (!member)
                return;
            member->events->open.store(false);
            cbb_member_stop(member->m);
        },
        [](napi_env env) { return undefined(env); });
}

// ---- joining by the phone's QR code or an invitation ----

// joinNew(request: string): Promise<{handle, answer}>; the phone joins as
// a member, signing with its member key.
napi_value joinNew(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    auto joiner = std::make_shared<cbb_join *>(nullptr);
    auto answer = std::make_shared<std::string>();
    return later(
        env,
        [req, joiner, answer]() {
            uint8_t *out = nullptr;
            size_t len = 0;
            *joiner = cbb_join_new(reinterpret_cast<const uint8_t *>(req.data()), req.size(), keys::signMember, nullptr, &out, &len);
            *answer = take(out, len);
        },
        [joiner, answer](napi_env env) { return made(env, *joiner, *answer); });
}

// joinAccept(handle): Promise<string>, a new attempt.
napi_value joinAccept(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_join *j = handleOf<cbb_join>(env, a.v[0]);
    return laterString(env, [j]() {
        size_t len = 0;
        return take(cbb_join_accept(j, &len), len);
    });
}

// joinFeed(handle, data: ArrayBuffer, nowMs: number): Promise<string>
napi_value joinFeed(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_join *j = handleOf<cbb_join>(env, a.v[0]);
    const std::vector<uint8_t> data = bytesOf(env, a.v[1]);
    const int64_t now = intOf(env, a.v[2]);
    return laterString(env, [j, data, now]() {
        size_t len = 0;
        return take(cbb_join_feed(j, data.data(), data.size(), now, &len), len);
    });
}

// joinFinish(handle, saved: boolean): Promise<string>
napi_value joinFinish(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_join *j = handleOf<cbb_join>(env, a.v[0]);
    const bool saved = boolOf(env, a.v[1]);
    return laterString(env, [j, saved]() {
        size_t len = 0;
        return take(cbb_join_finish(j, saved ? 1 : 0, &len), len);
    });
}

// joinAnnounce(handle, port): boolean
napi_value joinAnnounce(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_join *j = handleOf<cbb_join>(env, a.v[0]);
    return boolean(env, j && cbb_join_announce(j, uint16_t(intOf(env, a.v[1]))) == 1);
}

// joinAnswered(handle): boolean
napi_value joinAnswered(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const cbb_join *j = handleOf<cbb_join>(env, a.v[0]);
    return boolean(env, j && cbb_join_answered(j) == 1);
}

// joinFree(handle): Promise<void>; the invitation's tunnel closes on it.
napi_value joinFree(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_join *j = handleOf<cbb_join>(env, a.v[0]);
    return later(env, [j]() { cbb_join_free(j); }, [](napi_env env) { return undefined(env); });
}

// ---- admitting a device as an admin ----

// admitNew(member, request: string, which): Promise<{handle, answer}>
napi_value admitNew(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    const std::string req = stringOf(env, a.v[1]);
    const cbb_sign_fn sign = signerOf(whichOf(env, a.v[2]));
    auto admit = std::make_shared<cbb_admit *>(nullptr);
    auto answer = std::make_shared<std::string>();
    return later(
        env,
        [member, req, sign, admit, answer]() {
            if (!member) {
                *answer = errorAnswer({"", "admit: no member"});
                return;
            }
            uint8_t *out = nullptr;
            size_t len = 0;
            *admit = cbb_admit_new(member->m, reinterpret_cast<const uint8_t *>(req.data()), req.size(), sign, nullptr, &out, &len);
            *answer = take(out, len);
        },
        [admit, answer](napi_env env) { return made(env, *admit, *answer); });
}

// admitDial(handle): Promise<string>
napi_value admitDial(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_admit *ad = handleOf<cbb_admit>(env, a.v[0]);
    return laterString(env, [ad]() {
        size_t len = 0;
        return take(cbb_admit_dial(ad, &len), len);
    });
}

// admitFeed(handle, data: ArrayBuffer, nowMs): Promise<string>
napi_value admitFeed(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_admit *ad = handleOf<cbb_admit>(env, a.v[0]);
    const std::vector<uint8_t> data = bytesOf(env, a.v[1]);
    const int64_t now = intOf(env, a.v[2]);
    return laterString(env, [ad, data, now]() {
        size_t len = 0;
        return take(cbb_admit_feed(ad, data.data(), data.size(), now, &len), len);
    });
}

// admitFree(handle): Promise<void>
napi_value admitFree(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_admit *ad = handleOf<cbb_admit>(env, a.v[0]);
    return later(env, [ad]() { cbb_admit_free(ad); }, [](napi_env env) { return undefined(env); });
}

// ---- remote invitations ----

// inviteNew(member, request: string, which): Promise<{handle, answer}>
napi_value inviteNew(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    Member *member = handleOf<Member>(env, a.v[0]);
    const std::string req = stringOf(env, a.v[1]);
    const cbb_sign_fn sign = signerOf(whichOf(env, a.v[2]));
    auto invite = std::make_shared<cbb_invite *>(nullptr);
    auto answer = std::make_shared<std::string>();
    return later(
        env,
        [member, req, sign, invite, answer]() {
            if (!member) {
                *answer = errorAnswer({"", "invite: no member"});
                return;
            }
            uint8_t *out = nullptr;
            size_t len = 0;
            *invite = cbb_invite_new(member->m, reinterpret_cast<const uint8_t *>(req.data()), req.size(), sign, nullptr, &out, &len);
            *answer = take(out, len);
        },
        [invite, answer](napi_env env) { return made(env, *invite, *answer); });
}

// inviteNext(handle, version, timeoutMs): Promise<string>
napi_value inviteNext(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const cbb_invite *i = handleOf<cbb_invite>(env, a.v[0]);
    const auto version = uint64_t(intOf(env, a.v[1]));
    const auto timeout = uint64_t(intOf(env, a.v[2]));
    return laterString(env, [i, version, timeout]() {
        size_t len = 0;
        return take(cbb_invite_next(i, version, timeout, &len), len);
    });
}

// inviteAnswer(handle, yes: boolean): void
napi_value inviteAnswer(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const cbb_invite *i = handleOf<cbb_invite>(env, a.v[0]);
    if (i)
        cbb_invite_answer(i, boolOf(env, a.v[1]) ? 1 : 0);
    return undefined(env);
}

// inviteFree(handle): Promise<void>; waits for the window to close.
napi_value inviteFree(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    cbb_invite *i = handleOf<cbb_invite>(env, a.v[0]);
    return later(env, [i]() { cbb_invite_free(i); }, [](napi_env env) { return undefined(env); });
}

// ---- away from home ----

// tunnel(request: string): Promise<string>
napi_value tunnel(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    return laterString(env, [req]() {
        size_t len = 0;
        return take(cbb_tunnel(reinterpret_cast<const uint8_t *>(req.data()), req.size(), &len), len);
    });
}

// tunnelRegister(request: string): Promise<string>, signed with the member key.
napi_value tunnelRegister(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    return laterString(env, [req]() {
        size_t len = 0;
        return take(cbb_tunnel_register(reinterpret_cast<const uint8_t *>(req.data()), req.size(), keys::signMember, nullptr, &len), len);
    });
}

// tunnelRelay(request: string, onEvent): Promise<string>, signed with the
// member key; its events go to onEvent until the link stops.
napi_value tunnelRelay(napi_env env, napi_callback_info info)
{
    Args a(env, info);
    const std::string req = stringOf(env, a.v[0]);
    Events *events = eventsOf(env, a.v[1]);
    return laterString(env, [req, events]() {
        size_t len = 0;
        return take(cbb_tunnel_relay(reinterpret_cast<const uint8_t *>(req.data()), req.size(), keys::signMember, onEvent, events, &len),
                    len);
    });
}

// ---- the module ----

napi_value init(napi_env env, napi_value exports)
{
    const napi_property_descriptor fns[] = {
        {"abi", nullptr, abi, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"call", nullptr, call, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setAuth", nullptr, setAuth, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"keyEnsure", nullptr, keyEnsure, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"keyForget", nullptr, keyForget, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"groupNew", nullptr, groupNew, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"restore", nullptr, restore, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setCard", nullptr, setCard, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setWatch", nullptr, setWatch, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"piv", nullptr, piv, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"qrRead", nullptr, qrRead, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"memberStart", nullptr, memberStart, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"memberCall", nullptr, memberCall, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"memberManage", nullptr, memberManage, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"memberManageCard", nullptr, memberManageCard, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"memberManageWatch", nullptr, memberManageWatch, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"memberServers", nullptr, memberServers, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"memberStop", nullptr, memberStop, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"joinNew", nullptr, joinNew, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"joinAccept", nullptr, joinAccept, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"joinFeed", nullptr, joinFeed, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"joinFinish", nullptr, joinFinish, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"joinAnnounce", nullptr, joinAnnounce, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"joinAnswered", nullptr, joinAnswered, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"joinFree", nullptr, joinFree, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"admitNew", nullptr, admitNew, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"admitDial", nullptr, admitDial, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"admitFeed", nullptr, admitFeed, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"admitFree", nullptr, admitFree, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"inviteNew", nullptr, inviteNew, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"inviteNext", nullptr, inviteNext, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"inviteAnswer", nullptr, inviteAnswer, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"inviteFree", nullptr, inviteFree, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"tunnel", nullptr, tunnel, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"tunnelRegister", nullptr, tunnelRegister, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"tunnelRelay", nullptr, tunnelRelay, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(fns) / sizeof(fns[0]), fns);
    return exports;
}

napi_module cbbModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = init,
    .nm_modname = "cbb_napi",
    .nm_priv = nullptr,
    .reserved = {0},
};

} // namespace

extern "C" __attribute__((constructor)) void RegisterCbbNapiModule()
{
    napi_module_register(&cbbModule);
}
