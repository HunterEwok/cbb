// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "keys.h"

#include "der.h"

#include <huks/native_huks_api.h>
#include <huks/native_huks_param.h>
#include <huks/native_huks_type.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>

namespace keys {

namespace {

const char memberAlias[] = "cbb-member";
const char adminAlias[] = "cbb-admin";

std::string aliasOf(Which which)
{
    return which == Which::Admin ? adminAlias : memberAlias;
}

OH_Huks_Blob blobOf(const std::string &alias)
{
    return {uint32_t(alias.size()), reinterpret_cast<uint8_t *>(const_cast<char *>(alias.data()))};
}

std::string nameOf(Which which)
{
    return which == Which::Admin ? "admin key" : "member key";
}

std::string why(const char *what, const OH_Huks_Result &r)
{
    return std::string("huks: ") + what + ": " + std::to_string(r.errorCode) + (r.errorMsg ? std::string(" ") + r.errorMsg : std::string());
}

// A parameter set, freed when it goes out of scope.
class Params {
public:
    explicit Params(const OH_Huks_Param *params, uint32_t n)
    {
        if (OH_Huks_InitParamSet(&m_set).errorCode != OH_HUKS_SUCCESS)
            return;
        if (n && OH_Huks_AddParams(m_set, params, n).errorCode != OH_HUKS_SUCCESS)
            return;
        m_ok = OH_Huks_BuildParamSet(&m_set).errorCode == OH_HUKS_SUCCESS;
    }
    ~Params()
    {
        if (m_set)
            OH_Huks_FreeParamSet(&m_set);
    }
    Params(const Params &) = delete;
    Params &operator=(const Params &) = delete;
    OH_Huks_ParamSet *get() const { return m_ok ? m_set : nullptr; }

private:
    OH_Huks_ParamSet *m_set = nullptr;
    bool m_ok = false;
};

OH_Huks_Param uintParam(uint32_t tag, uint32_t v)
{
    OH_Huks_Param p{};
    p.tag = tag;
    p.uint32Param = v;
    return p;
}

// The signing parameters: ECDSA over the digest the core already made, so
// HUKS takes the 32 bytes as they are.
const OH_Huks_Param signParams[] = {
    uintParam(OH_HUKS_TAG_ALGORITHM, OH_HUKS_ALG_ECC),
    uintParam(OH_HUKS_TAG_KEY_SIZE, OH_HUKS_ECC_KEY_SIZE_256),
    uintParam(OH_HUKS_TAG_PURPOSE, OH_HUKS_KEY_PURPOSE_SIGN),
    uintParam(OH_HUKS_TAG_DIGEST, OH_HUKS_DIGEST_NONE),
};

// How long the user's consent lets the admin key sign, and how long the app
// reuses the token it got for it: a little less, so that HUKS never sees a
// token it already let lapse.
constexpr uint32_t authTimeoutSeconds = 30;
constexpr auto tokenReuse = std::chrono::seconds(25);

std::mutex authMu;
AuthFn authFn;
std::vector<uint8_t> lastToken;
std::chrono::steady_clock::time_point lastTokenAt;

} // namespace

namespace {

// Finds the key at alias, making it the first time; admin keys ask the
// user before they sign. what names it in the log.
bool ensureAt(const std::string &aliasName, bool admin, const std::string &what, Key *key, Failure *failure)
{
    OH_Huks_Blob alias = blobOf(aliasName);
    Params empty(nullptr, 0);
    OH_Huks_Result r = OH_Huks_IsKeyItemExist(&alias, empty.get());
    if (r.errorCode == OH_HUKS_ERR_CODE_ITEM_NOT_EXIST) {
        std::vector<OH_Huks_Param> gen = {
            uintParam(OH_HUKS_TAG_ALGORITHM, OH_HUKS_ALG_ECC),
            uintParam(OH_HUKS_TAG_KEY_SIZE, OH_HUKS_ECC_KEY_SIZE_256),
            uintParam(OH_HUKS_TAG_PURPOSE, OH_HUKS_KEY_PURPOSE_SIGN | OH_HUKS_KEY_PURPOSE_VERIFY),
            uintParam(OH_HUKS_TAG_DIGEST, OH_HUKS_DIGEST_NONE),
        };
        if (admin) {
            // The key signs only after the user's face, fingerprint or the
            // phone's PIN, for authTimeoutSeconds after it: one prompt for an
            // action, which may sign several times (a new group signs three
            // times). A new fingerprint or face does not void the key, a
            // removed lock screen does.
            gen.push_back(uintParam(OH_HUKS_TAG_USER_AUTH_TYPE,
                                    OH_HUKS_USER_AUTH_TYPE_FINGERPRINT | OH_HUKS_USER_AUTH_TYPE_FACE | OH_HUKS_USER_AUTH_TYPE_PIN));
            gen.push_back(uintParam(OH_HUKS_TAG_KEY_AUTH_ACCESS_TYPE, OH_HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD));
            gen.push_back(uintParam(OH_HUKS_TAG_CHALLENGE_TYPE, OH_HUKS_CHALLENGE_TYPE_NONE));
            gen.push_back(uintParam(OH_HUKS_TAG_AUTH_TIMEOUT, authTimeoutSeconds));
        }
        Params params(gen.data(), uint32_t(gen.size()));
        if (!params.get()) {
            *failure = {"The phone's keystore did not answer.", "huks: no parameter set for the " + what};
            return false;
        }
        r = OH_Huks_GenerateKeyItem(&alias, params.get(), nullptr);
        if (r.errorCode != OH_HUKS_SUCCESS) {
            *failure = {"The phone could not make its key.", why(("generate the " + what).c_str(), r)};
            return false;
        }
        key->created = true;
    } else if (r.errorCode != OH_HUKS_SUCCESS) {
        *failure = {"The phone's keystore did not answer.", why(("look for the " + what).c_str(), r)};
        return false;
    }
    uint8_t out[512];
    OH_Huks_Blob pub{sizeof(out), out};
    r = OH_Huks_ExportPublicKeyItem(&alias, empty.get(), &pub);
    if (r.errorCode != OH_HUKS_SUCCESS) {
        *failure = {"The phone's keystore did not answer.", why(("export the " + what).c_str(), r)};
        return false;
    }
    key->point = pointOf(pub.data, pub.size);
    if (key->point.empty()) {
        *failure = {"The phone's keystore gave a key CBB cannot read.",
                    "huks: the " + what + "'s public key is not a P-256 point (" + std::to_string(pub.size) + " bytes)"};
        return false;
    }
    return true;
}

} // namespace

bool ensure(Which which, Key *key, Failure *failure)
{
    return ensureAt(aliasOf(which), which == Which::Admin, nameOf(which), key, failure);
}

namespace {
bool forgetServerKeys(const std::vector<std::string> &keep, Failure *failure);
} // namespace

bool forget(Failure *failure)
{
    if (!forgetServerKeys({}, failure))
        return false;
    Params empty(nullptr, 0);
    for (const Which which : {Which::Member, Which::Admin}) {
        const std::string name = aliasOf(which);
        OH_Huks_Blob alias = blobOf(name);
        const OH_Huks_Result r = OH_Huks_DeleteKeyItem(&alias, empty.get());
        if (r.errorCode != OH_HUKS_SUCCESS && r.errorCode != OH_HUKS_ERR_CODE_ITEM_NOT_EXIST) {
            *failure = {"The phone could not delete its key.", why(("delete the " + nameOf(which)).c_str(), r)};
            return false;
        }
    }
    return true;
}

void setAuth(AuthFn auth)
{
    std::lock_guard<std::mutex> lock(authMu);
    authFn = std::move(auth);
}

namespace {

// The token of the user's consent for the admin key: the last one while it
// is fresh, else a new one, for which the app asks the user.
std::vector<uint8_t> consent(bool fresh, std::string *reason)
{
    AuthFn auth;
    {
        std::lock_guard<std::mutex> lock(authMu);
        if (!fresh && !lastToken.empty() && std::chrono::steady_clock::now() - lastTokenAt < tokenReuse)
            return lastToken;
        lastToken.clear();
        auth = authFn;
    }
    if (!auth) {
        *reason = "auth: no function for the user's consent";
        return {};
    }
    // The key's consent is by time, not by a challenge (CHALLENGE_TYPE_NONE).
    std::vector<uint8_t> token = auth({}, reason);
    if (!token.empty()) {
        std::lock_guard<std::mutex> lock(authMu);
        lastToken = token;
        lastTokenAt = std::chrono::steady_clock::now();
    }
    return token;
}

// One signing session; token is the consent for the admin key, empty for the
// member key.
OH_Huks_Result signOnceAt(const std::string &aliasName, const uint8_t *digest, const std::vector<uint8_t> &token, uint8_t *out,
                          uint32_t *outLen)
{
    OH_Huks_Blob alias = blobOf(aliasName);
    Params init(signParams, sizeof(signParams) / sizeof(signParams[0]));
    uint8_t handleBytes[8] = {};
    OH_Huks_Blob handle{sizeof(handleBytes), handleBytes};
    OH_Huks_Result r = OH_Huks_InitSession(&alias, init.get(), &handle, nullptr);
    if (r.errorCode != OH_HUKS_SUCCESS)
        return r;
    std::vector<OH_Huks_Param> finishParams(signParams, signParams + sizeof(signParams) / sizeof(signParams[0]));
    if (!token.empty()) {
        OH_Huks_Param t{};
        t.tag = OH_HUKS_TAG_AUTH_TOKEN;
        t.blob = {uint32_t(token.size()), const_cast<uint8_t *>(token.data())};
        finishParams.push_back(t);
    }
    Params finish(finishParams.data(), uint32_t(finishParams.size()));
    OH_Huks_Blob in{32, const_cast<uint8_t *>(digest)};
    OH_Huks_Blob sig{*outLen, out};
    r = OH_Huks_FinishSession(&handle, finish.get(), &in, &sig);
    *outLen = sig.size;
    return r;
}

OH_Huks_Result signOnce(Which which, const uint8_t *digest, const std::vector<uint8_t> &token, uint8_t *out, uint32_t *outLen)
{
    return signOnceAt(aliasOf(which), digest, token, out, outLen);
}

// A signature HUKS gave as DER, or as r||s, which it turns into DER.
bool derOf(const uint8_t *out, uint32_t outLen, std::vector<uint8_t> *der)
{
    if (outLen == 64 && out[0] != 0x30)
        *der = derSignature(out);
    else
        der->assign(out, out + outLen);
    return der->size() <= 72 && !der->empty() && (*der)[0] == 0x30;
}

} // namespace

bool sign(Which which, const uint8_t *digest, std::vector<uint8_t> *der, Failure *failure)
{
    uint8_t out[128];
    uint32_t outLen = sizeof(out);
    std::vector<uint8_t> token;
    std::string reason;
    if (which == Which::Admin) {
        token = consent(false, &reason);
        if (token.empty()) {
            *failure = {"The key did not sign without your consent.", reason};
            return false;
        }
    }
    OH_Huks_Result r = signOnce(which, digest, token, out, &outLen);
    // A reused token HUKS no longer takes: ask the user once more.
    if (which == Which::Admin &&
        (r.errorCode == OH_HUKS_ERR_CODE_KEY_AUTH_TIME_OUT || r.errorCode == OH_HUKS_ERR_CODE_KEY_AUTH_VERIFY_FAILED)) {
        token = consent(true, &reason);
        if (token.empty()) {
            *failure = {"The key did not sign without your consent.", reason};
            return false;
        }
        outLen = sizeof(out);
        r = signOnce(which, digest, token, out, &outLen);
    }
    if (r.errorCode != OH_HUKS_SUCCESS) {
        *failure = {"The phone's key did not sign.", why(("sign with the " + nameOf(which)).c_str(), r)};
        return false;
    }
    // HUKS gives ECDSA in DER; a raw r||s is turned into DER all the same.
    if (!derOf(out, outLen, der)) {
        *failure = {"The phone's key gave a signature CBB cannot read.", "huks: a signature of " + std::to_string(outLen) + " bytes"};
        return false;
    }
    return true;
}

namespace {

int32_t signFor(Which which, const uint8_t *digest, uint8_t *sig, size_t *sigLen)
{
    std::vector<uint8_t> der;
    Failure failure;
    if (!sign(which, digest, &der, &failure))
        return 1;
    std::memcpy(sig, der.data(), der.size());
    *sigLen = der.size();
    return 0;
}

} // namespace

int32_t signMember(void *, const uint8_t *digest, uint8_t *sig, size_t *sigLen)
{
    return signFor(Which::Member, digest, sig, sigLen);
}

int32_t signAdmin(void *, const uint8_t *digest, uint8_t *sig, size_t *sigLen)
{
    return signFor(Which::Admin, digest, sig, sigLen);
}

// The keys for the servers.

namespace {

std::mutex serverMu;
std::string serverIndex; // the file that lists the keys for the servers made

const char serverPrefix[] = "cbb-srv-";

// The alias of the key for the servers the core names name ("server TAG",
// "period TAG"): the prefix and the name with its space as a dash.
std::string serverAlias(const std::string &name)
{
    std::string a = serverPrefix + name;
    std::replace(a.begin(), a.end(), ' ', '-');
    return a;
}

std::vector<std::string> readIndex()
{
    std::vector<std::string> names;
    if (serverIndex.empty())
        return names;
    std::ifstream f(serverIndex);
    for (std::string line; std::getline(f, line);) {
        if (!line.empty())
            names.push_back(line);
    }
    return names;
}

bool writeIndex(const std::vector<std::string> &names)
{
    if (serverIndex.empty())
        return false;
    const std::string tmp = serverIndex + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        for (const auto &n : names)
            f << n << '\n';
        if (!f)
            return false;
    }
    return std::rename(tmp.c_str(), serverIndex.c_str()) == 0;
}

bool forgetServerKeys(const std::vector<std::string> &keep, Failure *failure)
{
    std::lock_guard<std::mutex> lock(serverMu);
    std::vector<std::string> left;
    Params empty(nullptr, 0);
    for (const auto &name : readIndex()) {
        if (std::find(keep.begin(), keep.end(), name) != keep.end()) {
            left.push_back(name);
            continue;
        }
        const std::string a = serverAlias(name);
        OH_Huks_Blob alias = blobOf(a);
        const OH_Huks_Result r = OH_Huks_DeleteKeyItem(&alias, empty.get());
        if (r.errorCode != OH_HUKS_SUCCESS && r.errorCode != OH_HUKS_ERR_CODE_ITEM_NOT_EXIST) {
            *failure = {"The phone could not delete its key.", why(("delete the key " + name).c_str(), r)};
            left.push_back(name);
        }
    }
    if (!serverIndex.empty() && !writeIndex(left) && !failure->failed())
        *failure = {"The phone could not keep the list of its keys.", "keys: cannot write " + serverIndex};
    return !failure->failed();
}

} // namespace

void setServerIndex(const std::string &path)
{
    std::lock_guard<std::mutex> lock(serverMu);
    serverIndex = path;
}

int32_t serverKeys(void *, int32_t op, const uint8_t *name, size_t nameLen, const uint8_t *digest, uint8_t *out, size_t *outLen)
{
    const std::string n(reinterpret_cast<const char *>(name), nameLen);
    switch (op) {
    case 0: { // has
        const std::string a = serverAlias(n);
        OH_Huks_Blob alias = blobOf(a);
        Params empty(nullptr, 0);
        return OH_Huks_IsKeyItemExist(&alias, empty.get()).errorCode == OH_HUKS_SUCCESS ? 0 : 1;
    }
    case 1: { // the public key, made first
        Key key;
        Failure failure;
        {
            std::lock_guard<std::mutex> lock(serverMu);
            if (!ensureAt(serverAlias(n), false, "key " + n, &key, &failure))
                return 1;
            if (key.created) {
                std::vector<std::string> names = readIndex();
                if (std::find(names.begin(), names.end(), n) == names.end())
                    names.push_back(n);
                writeIndex(names);
            }
        }
        if (key.point.size() > 72)
            return 1;
        std::memcpy(out, key.point.data(), key.point.size());
        *outLen = key.point.size();
        return 0;
    }
    case 2: { // sign
        uint8_t sig[128];
        uint32_t sigLen = sizeof(sig);
        if (signOnceAt(serverAlias(n), digest, {}, sig, &sigLen).errorCode != OH_HUKS_SUCCESS)
            return 1;
        std::vector<uint8_t> der;
        if (!derOf(sig, sigLen, &der))
            return 1;
        std::memcpy(out, der.data(), der.size());
        *outLen = der.size();
        return 0;
    }
    case 3: { // keep only these, one a line
        std::vector<std::string> keep;
        std::istringstream lines(n);
        for (std::string line; std::getline(lines, line);)
            keep.push_back(line);
        Failure failure;
        return forgetServerKeys(keep, &failure) ? 0 : 1;
    }
    default:
        return 1;
    }
}

} // namespace keys
