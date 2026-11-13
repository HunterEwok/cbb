// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "keystore.h"

#include "../pinrule.h"

#include "pkcs11.h"
#include "qcainit.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QMutex>
#include <QSettings>
#include <QStandardPaths>
#include <QThread>
#include <QVector>

#include <dlfcn.h>
#include <cstring>
#include <memory>

using namespace pkcs11;

namespace KeyStore {

namespace {

// The labels of each key's two halves.
QByteArray labelOf(Which which)
{
    return which == Which::Admin ? QByteArrayLiteral("cbb-admin") : QByteArrayLiteral("cbb-member");
}

// The admin key's token: the slot Aurora's TA names "APP", the app's own
// as the QCA token "USERAPP" is (measured on the R570E, 2026-11-09: another
// app sees it uninitialized), which the app initializes itself.
const char adminSerial[] = "APP";
const char adminTokenLabel[] = "CBB admin";

// The settings the PIN keeps beside the token: whether the token's SO PIN
// is the random one yet, whether a left key waits to be replaced, and the
// wrong PINs since the last right one (the TEE counts its own; the app
// keeps this one only to say how many are left).
const QString soRandomKey = QStringLiteral("keys/admin_so_random");
const QString staleKey = QStringLiteral("keys/admin_stale");
const QString wrongKey = QStringLiteral("keys/admin_wrong");
// Set once the member key's token was seen: from then on it is never made
// again, since making it wipes the member key in it.
const QString memberTokenKey = QStringLiteral("keys/member_token");

// Whether the member key's token must already be there: the app saw it
// before, or the phone is in a group, whose certificate names the key.
bool memberTokenKnown()
{
    return QSettings().value(memberTokenKey).toBool()
        || QFile::exists(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QStringLiteral("/member.json"));
}
// The tries Aurora's TA gives a user PIN before it locks (measured).
const int pinTries = 7;
// How long the admin token stays logged in after its last use.
const qint64 pinHoldMs = 5 * 60 * 1000;

QString hex(CK_RV rv) { return QStringLiteral("0x%1").arg(rv, 0, 16); }

QString fixed(const unsigned char *s, int n)
{
    // Token labels are padded with spaces or, from QCA, with NUL bytes.
    int len = n;
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\0'))
        --len;
    return QString::fromLatin1(reinterpret_cast<const char *>(s), len);
}

void wipe(QByteArray *b)
{
    if (!b->isEmpty())
        std::memset(b->data(), 0, size_t(b->size()));
    b->clear();
}

// libckteec, loaded and initialized once for every Token that uses it and
// finalized when the last one goes: C_Finalize ends every session of the
// process, the kept login's too.
QMutex libLock;
void *libHandle = nullptr;
CK_FUNCTION_LIST *libList = nullptr;
int libUsers = 0;

QByteArray randomPin()
{
    QFile f(QStringLiteral("/dev/urandom"));
    if (!f.open(QIODevice::ReadOnly))
        return QByteArray();
    const QByteArray raw = f.read(24);
    return raw.size() == 24 ? raw.toBase64() : QByteArray();
}

const unsigned char *bytes(const QByteArray &b) { return reinterpret_cast<const unsigned char *>(b.constData()); }

// A session in one of the app's tokens, logged out and closed when it goes
// out of scope.
class Token
{
public:
    ~Token()
    {
        if (m_session) {
            if (m_loggedIn)
                m_f->C_Logout(m_session);
            m_f->C_CloseSession(m_session);
        }
        if (m_f) {
            QMutexLocker l(&libLock);
            if (--libUsers == 0) {
                libList->C_Finalize(nullptr);
                dlclose(libHandle);
                libList = nullptr;
                libHandle = nullptr;
            }
        }
    }

    // Opens libckteec. NoTee without OP-TEE.
    State load(Failure *failure)
    {
        if (!QFile::exists(QStringLiteral("/dev/tee0"))) {
            *failure = {QCoreApplication::translate("Errors", "This phone has no secure element for keys."), QStringLiteral("tee: no /dev/tee0")};
            return State::NoTee;
        }
        QMutexLocker l(&libLock);
        if (!libList) {
            void *lib = dlopen("libckteec.so.0", RTLD_NOW);
            if (!lib) {
                *failure = {QCoreApplication::translate("Errors", "This phone has no secure element for keys."),
                            QStringLiteral("tee: %1").arg(QString::fromLocal8Bit(dlerror()))};
                return State::NoTee;
            }
            auto getList = reinterpret_cast<CK_RV (*)(CK_FUNCTION_LIST **)>(dlsym(lib, "C_GetFunctionList"));
            CK_FUNCTION_LIST *f = nullptr;
            CK_RV rv = getList ? getList(&f) : CK_RV(~0ul);
            if (rv == CKR_OK && f) {
                rv = f->C_Initialize(nullptr);
                if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
                    rv = CKR_OK;
            }
            if (rv != CKR_OK || !f) {
                dlclose(lib);
                return fail(failure, QStringLiteral("C_GetFunctionList or C_Initialize: %1").arg(hex(rv)));
            }
            libHandle = lib;
            libList = f;
        }
        ++libUsers;
        m_f = libList;
        return State::Ready;
    }

    // Finds the token QCA initialized for this app, the first time
    // initializing it, and logs in with QCA's PIN: the member key's token.
    State openMember(Failure *failure)
    {
        const State loaded = load(failure);
        if (loaded != State::Ready)
            return loaded;
        CK_FUNCTION_LIST *f = m_f;
        CK_SLOT_ID slot = 0;
        CK_TOKEN_INFO info;
        Found found = findToken(&slot, &info);
        // A token the app saw before and does not see now is a TEE that has
        // not answered yet (as right after the app's last run let go of it),
        // never a reason to make it again: that would wipe the member key.
        for (int i = 0; i < 5 && found != Found::Yes && (found == Found::Unreadable || memberTokenKnown()); ++i) {
            QThread::msleep(400);
            found = findToken(&slot, &info);
        }
        if (found == Found::Unreadable)
            return fail(failure, QStringLiteral("the TEE's slots do not read"));
        if (found == Found::No && memberTokenKnown())
            return fail(failure, QStringLiteral("the token \"%1\" is not there, though the app saw it before or is in a group; not making it again").arg(QLatin1String(QcaInit::tokenLabel)));
        if (found == Found::No) {
            // Never initialized: the first run after the app was installed.
            // QCA's plugin opens libckteec in this process too, so the app
            // lets go of it until QCA is done, which only this Token may do.
            QMutexLocker l(&libLock);
            if (libUsers != 1)
                return fail(failure, QStringLiteral("the TEE is busy while its first token is made"));
            f->C_Finalize(nullptr);
            const Failure qca = QcaInit::initUserAppKeystore();
            const CK_RV rv = f->C_Initialize(nullptr);
            if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                // Nothing to finalize now: the destructor leaves the library be.
                --libUsers;
                libList = nullptr;
                dlclose(libHandle);
                libHandle = nullptr;
                m_f = nullptr;
                return fail(failure, QStringLiteral("C_Initialize after QCA: %1").arg(hex(rv)));
            }
            if (!qca.isNull()) {
                *failure = qca;
                return State::Failed;
            }
            l.unlock();
            if (findToken(&slot, &info) != Found::Yes)
                return fail(failure, QStringLiteral("no token \"%1\" after QCA initialized USERAPP").arg(QLatin1String(QcaInit::tokenLabel)));
        }
        QSettings().setValue(memberTokenKey, true);
        const QString model = fixed(info.model, 16);
        if (model != QLatin1String("Aurora TA"))
            return fail(failure, QStringLiteral("the token's model is \"%1\", not Aurora TA").arg(model));

        CK_RV rv = m_f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &m_session);
        if (rv != CKR_OK)
            return fail(failure, QStringLiteral("C_OpenSession: %1").arg(hex(rv)));
        if ((info.flags & CKF_LOGIN_REQUIRED) && (info.flags & CKF_USER_PIN_INITIALIZED)) {
            // Only while no wrong PIN was tried: the app never spends the
            // token's tries.
            if (info.flags & (CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED))
                return fail(failure, QStringLiteral("the token shows failed PIN tries (flags %1)").arg(hex(info.flags)));
            const CK_ULONG len = CK_ULONG(std::strlen(QcaInit::pin));
            rv = m_f->C_Login(m_session, CKU_USER, reinterpret_cast<const unsigned char *>(QcaInit::pin), len);
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
                return fail(failure, QStringLiteral("C_Login: %1").arg(hex(rv)));
            // QCA's token stays logged in for the member key, which signs in
            // the background.
        }
        return State::Ready;
    }

    // Finds the admin key's token, initialized or not, and opens a session
    // in it, logged out. info is its state.
    State openAdmin(CK_TOKEN_INFO *info, Failure *failure)
    {
        const State loaded = load(failure);
        if (loaded != State::Ready)
            return loaded;
        CK_ULONG count = 0;
        if (m_f->C_GetSlotList(1, nullptr, &count) != CKR_OK || count == 0)
            return fail(failure, QStringLiteral("no slots"));
        QVector<CK_SLOT_ID> ids(static_cast<int>(count));
        if (m_f->C_GetSlotList(1, ids.data(), &count) != CKR_OK)
            return fail(failure, QStringLiteral("C_GetSlotList"));
        for (CK_ULONG i = 0; i < count; ++i) {
            CK_TOKEN_INFO t;
            std::memset(&t, 0, sizeof t);
            if (m_f->C_GetTokenInfo(ids[int(i)], &t) != CKR_OK)
                continue;
            if (fixed(t.serialNumber, 16) == QLatin1String(adminSerial) && fixed(t.model, 16) == QLatin1String("Aurora TA")) {
                m_slot = ids[int(i)];
                *info = t;
                if (!(t.flags & CKF_TOKEN_INITIALIZED))
                    return State::Ready; // no session in an uninitialized token
                const CK_RV rv = m_f->C_OpenSession(m_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &m_session);
                if (rv != CKR_OK)
                    return fail(failure, QStringLiteral("C_OpenSession admin: %1").arg(hex(rv)));
                return State::Ready;
            }
        }
        return fail(failure, QStringLiteral("no token with the serial %1").arg(QLatin1String(adminSerial)));
    }

    bool refresh(CK_TOKEN_INFO *info)
    {
        std::memset(info, 0, sizeof *info);
        return m_f->C_GetTokenInfo(m_slot, info) == CKR_OK;
    }

    CK_RV login(CK_ULONG who, const QByteArray &pin)
    {
        const CK_RV rv = m_f->C_Login(m_session, who, bytes(pin), CK_ULONG(pin.size()));
        if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN)
            m_loggedIn = true;
        return rv == CKR_USER_ALREADY_LOGGED_IN ? CKR_OK : rv;
    }

    void logout()
    {
        if (m_loggedIn)
            m_f->C_Logout(m_session);
        m_loggedIn = false;
    }

    // Whether the session's user is still logged in.
    bool userLoggedIn()
    {
        CK_SESSION_INFO si;
        std::memset(&si, 0, sizeof si);
        return m_session && m_f->C_GetSessionInfo(m_session, &si) == CKR_OK && si.state == CKS_RW_USER_FUNCTIONS;
    }

    // Initializes the admin token with pin as its SO PIN for now, then sets
    // the user PIN; randomizeSo makes the SO PIN random after.
    CK_RV initAdmin(const QByteArray &pin)
    {
        QByteArray label(adminTokenLabel);
        label.append(QByteArray(32 - label.size(), ' '));
        CK_RV rv = m_f->C_InitToken(m_slot, bytes(pin), CK_ULONG(pin.size()), bytes(label));
        if (rv != CKR_OK)
            return rv;
        rv = m_f->C_OpenSession(m_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &m_session);
        return rv;
    }

    // As SO with pin: sets the user PIN to pin.
    CK_RV initUserPin(const QByteArray &pin)
    {
        CK_RV rv = login(CKU_SO, pin);
        if (rv != CKR_OK)
            return rv;
        rv = m_f->C_InitPIN(m_session, bytes(pin), CK_ULONG(pin.size()));
        logout();
        return rv;
    }

    // As SO with pin: sets a random SO PIN, kept nowhere, so that nothing
    // can unlock or reset the user PIN. *notSo tells that the token refused
    // pin as the SO PIN (wrong, of a length it does not take, or locked by
    // such tries): the SO PIN is not the user PIN, so it was made random
    // before.
    CK_RV randomizeSo(const QByteArray &pin, bool *notSo)
    {
        *notSo = false;
        QByteArray so = randomPin();
        if (so.isEmpty())
            return CKR_GENERAL_ERROR;
        CK_RV rv = login(CKU_SO, pin);
        if (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LEN_RANGE || rv == CKR_PIN_INVALID || rv == CKR_PIN_LOCKED)
            *notSo = true;
        else if (rv == CKR_OK)
            rv = m_f->C_SetPIN(m_session, bytes(pin), CK_ULONG(pin.size()), bytes(so), CK_ULONG(so.size()));
        logout();
        wipe(&so);
        return rv;
    }

    CK_RV setUserPin(const QByteArray &old, const QByteArray &pin)
    {
        return m_f->C_SetPIN(m_session, bytes(old), CK_ULONG(old.size()), bytes(pin), CK_ULONG(pin.size()));
    }

    QVector<CK_OBJECT_HANDLE> find(CK_ULONG cls, QByteArray label)
    {
        CK_ATTRIBUTE t[] = {{CKA_CLASS, &cls, sizeof cls}, {CKA_LABEL, label.data(), CK_ULONG(label.size())}};
        QVector<CK_OBJECT_HANDLE> out;
        if (m_f->C_FindObjectsInit(m_session, t, 2) != CKR_OK)
            return out;
        CK_OBJECT_HANDLE found[8];
        CK_ULONG n = 0;
        m_f->C_FindObjects(m_session, found, 8, &n);
        m_f->C_FindObjectsFinal(m_session);
        for (CK_ULONG i = 0; i < n; ++i)
            out.append(found[i]);
        return out;
    }

    CK_RV generate(CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv, QByteArray label)
    {
        CK_BBOOL yes = 1, no = 0;
        // The template the R570E was measured with (2026-11-06): the curve
        // names the key type.
        QByteArray params = QByteArray::fromHex("06082a8648ce3d030107"); // prime256v1
        QByteArray id = QCryptographicHash::hash(label, QCryptographicHash::Sha256).left(8);
        CK_ATTRIBUTE pubT[] = {
            {CKA_TOKEN, &yes, 1},
            {CKA_PRIVATE, &no, 1},
            {CKA_VERIFY, &yes, 1},
            {CKA_EC_PARAMS, params.data(), CK_ULONG(params.size())},
            {CKA_LABEL, label.data(), CK_ULONG(label.size())},
            {CKA_ID, id.data(), CK_ULONG(id.size())},
        };
        CK_ATTRIBUTE privT[] = {
            {CKA_TOKEN, &yes, 1},
            {CKA_PRIVATE, &yes, 1},
            {CKA_SIGN, &yes, 1},
            {CKA_SENSITIVE, &yes, 1},
            {CKA_EXTRACTABLE, &no, 1},
            {CKA_LABEL, label.data(), CK_ULONG(label.size())},
            {CKA_ID, id.data(), CK_ULONG(id.size())},
        };
        CK_MECHANISM gen = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
        return m_f->C_GenerateKeyPair(m_session, &gen, pubT, 6, privT, 7, pub, priv);
    }

    CK_RV destroy(CK_OBJECT_HANDLE h) { return m_f->C_DestroyObject(m_session, h); }

    bool flag(CK_OBJECT_HANDLE h, CK_ULONG type)
    {
        CK_BBOOL v = 0;
        CK_ATTRIBUTE a = {type, &v, 1};
        return m_f->C_GetAttributeValue(m_session, h, &a, 1) == CKR_OK && v == 1;
    }

    // The public key's point, without the DER OCTET STRING PKCS#11 wraps it in.
    QByteArray point(CK_OBJECT_HANDLE pub)
    {
        unsigned char buf[80];
        CK_ATTRIBUTE a = {CKA_EC_POINT, buf, sizeof buf};
        if (m_f->C_GetAttributeValue(m_session, pub, &a, 1) != CKR_OK || a.ulValueLen > sizeof buf)
            return QByteArray();
        QByteArray p(reinterpret_cast<const char *>(buf), int(a.ulValueLen));
        if (p.size() == 67 && p.at(0) == 0x04 && p.at(1) == 65)
            p = p.mid(2);
        return p.size() == 65 && p.at(0) == 0x04 ? p : QByteArray();
    }

    QByteArray sign(CK_OBJECT_HANDLE priv, const QByteArray &digest, CK_RV *rv)
    {
        CK_MECHANISM m = {CKM_ECDSA, nullptr, 0};
        unsigned char sig[72];
        CK_ULONG len = sizeof sig;
        *rv = m_f->C_SignInit(m_session, &m, priv);
        if (*rv == CKR_OK)
            *rv = m_f->C_Sign(m_session, reinterpret_cast<const unsigned char *>(digest.constData()), CK_ULONG(digest.size()), sig, &len);
        return *rv == CKR_OK ? QByteArray(reinterpret_cast<const char *>(sig), int(len)) : QByteArray();
    }

    State fail(Failure *failure, const QString &why)
    {
        *failure = {QCoreApplication::translate("Errors", "The phone's secure element did not answer."), QStringLiteral("tee: ") + why};
        return State::Failed;
    }

private:
    // Yes: the token QCA initialized for this app, labelled CBB. No: the
    // slots read, and the app's QCA slot ("USERAPP") is there but not
    // initialized, the first run's state. Unreadable: anything else, which
    // never leads to making the token.
    enum class Found { Yes, No, Unreadable };
    Found findToken(CK_SLOT_ID *slot, CK_TOKEN_INFO *info)
    {
        CK_ULONG count = 0;
        if (m_f->C_GetSlotList(1, nullptr, &count) != CKR_OK || count == 0)
            return Found::Unreadable;
        QVector<CK_SLOT_ID> slotIds(static_cast<int>(count));
        if (m_f->C_GetSlotList(1, slotIds.data(), &count) != CKR_OK)
            return Found::Unreadable;
        bool fresh = false;
        for (CK_ULONG i = 0; i < count; ++i) {
            CK_TOKEN_INFO t;
            std::memset(&t, 0, sizeof t);
            if (m_f->C_GetTokenInfo(slotIds[int(i)], &t) != CKR_OK)
                return Found::Unreadable;
            if ((t.flags & CKF_TOKEN_INITIALIZED) && fixed(t.label, 32) == QLatin1String(QcaInit::tokenLabel)) {
                *slot = slotIds[int(i)];
                *info = t;
                return Found::Yes;
            }
            if (fixed(t.serialNumber, 16) == QLatin1String("USERAPP") && !(t.flags & CKF_TOKEN_INITIALIZED))
                fresh = true;
        }
        return fresh ? Found::No : Found::Unreadable;
    }

    CK_FUNCTION_LIST *m_f = nullptr;
    CK_SLOT_ID m_slot = 0;
    CK_SESSION_HANDLE m_session = 0;
    bool m_loggedIn = false;
};

// The admin token's session that stays logged in after the right PIN, so
// that the PIN itself is wiped at once: only the TEE holds it. It is used
// under its lock and logged out once unused for pinHoldMs.
QMutex keptLock;
std::unique_ptr<Token> kept;
QElapsedTimer keptUsed;

void keep(std::unique_ptr<Token> token)
{
    QMutexLocker l(&keptLock);
    kept = std::move(token);
    keptUsed.restart();
}

// Whether the kept login lasts, ending it once it does not; keptLock held.
bool keptAlive()
{
    if (kept && keptUsed.isValid() && keptUsed.elapsed() <= pinHoldMs && kept->userLoggedIn())
        return true;
    kept.reset();
    return false;
}

// Runs use on the logged-in admin token while the login lasts, which renews
// it; false, and nothing run, when the PIN is needed again.
template <typename Use> bool withLogin(Use use)
{
    QMutexLocker l(&keptLock);
    if (!keptAlive())
        return false;
    keptUsed.restart();
    use(*kept);
    return true;
}

PinStatus statusOf(const CK_TOKEN_INFO &info)
{
    PinStatus s;
    if (!(info.flags & CKF_TOKEN_INITIALIZED) || !(info.flags & CKF_USER_PIN_INITIALIZED))
        s.state = PinState::NotSet;
    else if (info.flags & CKF_USER_PIN_LOCKED)
        s.state = PinState::Locked;
    else
        s.state = PinState::Set;
    s.fewLeft = info.flags & CKF_USER_PIN_COUNT_LOW;
    s.lastTry = info.flags & CKF_USER_PIN_FINAL_TRY;
    // The token says whether a wrong PIN was tried and whether one try is
    // left; the app's own count only fills in between, and only while it
    // agrees with the token: after the app's data was cleared it is gone,
    // so the number is unknown (0) rather than a full seven.
    const int counted = QSettings().value(wrongKey).toInt();
    if (s.lastTry)
        s.triesLeft = 1;
    else if (!s.fewLeft)
        s.triesLeft = pinTries;
    else if (counted > 0)
        s.triesLeft = qBound(2, pinTries - counted, pinTries - 1);
    else
        s.triesLeft = 0;
    return s;
}

// A PIN the user chooses that the rule (pinrule.h) refuses; the dialogs
// check it first, so this is only the store's own guard.
PinResult pinTooSimple(Failure *failure, PinStatus *after)
{
    *failure = {QCoreApplication::translate("Errors", "Choose a PIN of at least six digits that is not easy to guess."),
                QStringLiteral("tee: the new PIN does not pass the PIN rule")};
    after->state = PinState::Failed;
    after->failure = *failure;
    return PinResult::Failed;
}

bool passesRule(const QByteArray &pin)
{
    return PinRule::check(pin.toStdString()) == PinRule::Verdict::Ok;
}

PinResult pinFailed(Failure *failure, PinStatus *after, const QString &why)
{
    *failure = {QCoreApplication::translate("Errors", "The phone's secure element did not take the PIN."), QStringLiteral("tee: ") + why};
    after->state = PinState::Failed;
    after->failure = *failure;
    return PinResult::Failed;
}

Failure pinMissing()
{
    return {QCoreApplication::translate("Errors", "The admin PIN is needed first."), QStringLiteral("tee: the admin PIN is not held")};
}

// Makes the admin key in the logged-in token, replacing a left one.
Key makeAdmin(Token &token)
{
    Key key;
    const QByteArray keyLabel = labelOf(Which::Admin);
    for (const CK_ULONG cls : {CKO_PRIVATE_KEY, CKO_PUBLIC_KEY})
        for (const CK_OBJECT_HANDLE h : token.find(cls, keyLabel))
            token.destroy(h);
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    const CK_RV rv = token.generate(&pub, &priv, keyLabel);
    if (rv != CKR_OK) {
        key.failure = {QCoreApplication::translate("Errors", "The phone's secure element did not make a key."), QStringLiteral("tee: C_GenerateKeyPair admin: %1").arg(hex(rv))};
        return key;
    }
    if (!token.flag(priv, CKA_TOKEN) || !token.flag(priv, CKA_NEVER_EXTRACTABLE) || !token.flag(priv, CKA_ALWAYS_SENSITIVE)) {
        key.failure = {QCoreApplication::translate("Errors", "The phone's key is not kept in its secure element."),
                       QStringLiteral("tee: the admin key is not a token key that is never extractable and always sensitive")};
        return key;
    }
    key.publicKey = token.point(pub);
    if (key.publicKey.isEmpty()) {
        key.failure = {QCoreApplication::translate("Errors", "The phone's secure element did not answer."), QStringLiteral("tee: the admin key's point does not read")};
        return key;
    }
    QSettings().remove(staleKey);
    key.created = true;
    key.state = State::Ready;
    return key;
}

// Whether an admin key of a version before the PIN is left in the member
// key's token: the group's root certified that key, so a new one behind the
// PIN would not match the phone's admin CA.
bool legacyAdmin()
{
    Token token;
    Failure ignored;
    return token.openMember(&ignored) == State::Ready && !token.find(CKO_PRIVATE_KEY, labelOf(Which::Admin)).isEmpty();
}

Key ensureAdmin()
{
    Key key;
    if (legacyAdmin()) {
        // Leaving the group deletes it (forget), and joining again as an
        // admin makes the key behind the PIN.
        key.state = State::Failed;
        key.failure = {QCoreApplication::translate("Errors", "This phone's admin key predates the admin PIN. Leave the group and join it again."),
                       QStringLiteral("tee: an admin key is left in the QCA token")};
        return key;
    }
    Token token;
    CK_TOKEN_INFO info;
    key.state = token.openAdmin(&info, &key.failure);
    if (key.state != State::Ready)
        return key;
    key.state = State::Failed;
    if (statusOf(info).state == PinState::NotSet) {
        key.pinNeeded = true;
        key.failure = pinMissing();
        return key;
    }
    const QByteArray keyLabel = labelOf(Which::Admin);
    const bool stale = QSettings().value(staleKey).toBool();
    // The public half reads without the PIN.
    const QVector<CK_OBJECT_HANDLE> pubs = token.find(CKO_PUBLIC_KEY, keyLabel);
    if (pubs.size() == 1 && !stale) {
        key.publicKey = token.point(pubs.first());
        if (!key.publicKey.isEmpty()) {
            key.state = State::Ready;
            return key;
        }
    }
    const bool logged = withLogin([&](Token &in) {
        // A key the token hid from the session logged out, kept unless the
        // phone left its group since.
        const QVector<CK_OBJECT_HANDLE> privs = in.find(CKO_PRIVATE_KEY, keyLabel), pubs2 = in.find(CKO_PUBLIC_KEY, keyLabel);
        if (!stale && privs.size() == 1 && pubs2.size() == 1) {
            key.publicKey = in.point(pubs2.first());
            if (!key.publicKey.isEmpty()) {
                key.state = State::Ready;
                return;
            }
        }
        key = makeAdmin(in);
    });
    if (!logged) {
        key.pinNeeded = true;
        key.failure = pinMissing();
    }
    return key;
}

QByteArray signAdmin(const QByteArray &digest, Failure *failure, bool *pinNeeded)
{
    QByteArray out;
    const bool logged = withLogin([&](Token &in) {
        const QVector<CK_OBJECT_HANDLE> privs = in.find(CKO_PRIVATE_KEY, labelOf(Which::Admin));
        if (privs.size() != 1) {
            *failure = {QCoreApplication::translate("Errors", "The phone's key is missing."), QStringLiteral("tee: %1 private admin keys").arg(privs.size())};
            return;
        }
        CK_RV rv = CKR_OK;
        const QByteArray raw = in.sign(privs.first(), digest, &rv);
        if (raw.size() != 64) {
            *failure = {QCoreApplication::translate("Errors", "The phone's secure element did not sign."), QStringLiteral("tee: C_Sign admin: %1, %2 bytes").arg(hex(rv)).arg(raw.size())};
            return;
        }
        out = derSignature(raw);
    });
    if (!logged) {
        if (pinNeeded)
            *pinNeeded = true;
        *failure = pinMissing();
    }
    return out;
}

} // namespace

QString store()
{
    return QStringLiteral("hardware");
}

Key ensure(Which which)
{
    if (which == Which::Admin)
        return ensureAdmin();
    Key key;
    Token token;
    key.state = token.openMember(&key.failure);
    if (key.state != State::Ready)
        return key;

    const QByteArray keyLabel = labelOf(which);
    const QVector<CK_OBJECT_HANDLE> privs = token.find(CKO_PRIVATE_KEY, keyLabel), pubs = token.find(CKO_PUBLIC_KEY, keyLabel);
    CK_OBJECT_HANDLE priv = 0, pub = 0;
    if (privs.size() == 1 && pubs.size() == 1) {
        priv = privs.first();
        pub = pubs.first();
    } else if (privs.isEmpty() && pubs.isEmpty()) {
        const CK_RV rv = token.generate(&pub, &priv, keyLabel);
        if (rv != CKR_OK) {
            key.state = State::Failed;
            key.failure = {QCoreApplication::translate("Errors", "The phone's secure element did not make a key."), QStringLiteral("tee: C_GenerateKeyPair: %1").arg(hex(rv))};
            return key;
        }
        key.created = true;
    } else {
        key.state = State::Failed;
        key.failure = {QCoreApplication::translate("Errors", "The phone's secure element holds a broken key."),
                       QStringLiteral("tee: %1 private and %2 public halves labelled %3").arg(privs.size()).arg(pubs.size()).arg(QLatin1String(keyLabel))};
        return key;
    }

    if (!token.flag(priv, CKA_TOKEN) || !token.flag(priv, CKA_NEVER_EXTRACTABLE) || !token.flag(priv, CKA_ALWAYS_SENSITIVE)) {
        key.state = State::Failed;
        key.failure = {QCoreApplication::translate("Errors", "The phone's key is not kept in its secure element."),
                       QStringLiteral("tee: the private key is not a token key that is never extractable and always sensitive")};
        return key;
    }
    key.publicKey = token.point(pub);
    if (key.publicKey.isEmpty()) {
        key.state = State::Failed;
        key.failure = {QCoreApplication::translate("Errors", "The phone's secure element did not answer."), QStringLiteral("tee: the public key's point does not read")};
    }
    return key;
}

QByteArray sign(const QByteArray &digest, Failure *failure, Which which, bool *pinNeeded)
{
    if (which == Which::Admin)
        return signAdmin(digest, failure, pinNeeded);
    Token token;
    if (token.openMember(failure) != State::Ready)
        return QByteArray();
    const QByteArray keyLabel = labelOf(which);
    const QVector<CK_OBJECT_HANDLE> privs = token.find(CKO_PRIVATE_KEY, keyLabel);
    if (privs.size() != 1) {
        *failure = {QCoreApplication::translate("Errors", "The phone's key is missing."), QStringLiteral("tee: %1 private keys labelled %2").arg(privs.size()).arg(QLatin1String(keyLabel))};
        return QByteArray();
    }
    CK_RV rv = 0;
    const QByteArray raw = token.sign(privs.first(), digest, &rv);
    if (raw.size() != 64) {
        *failure = {QCoreApplication::translate("Errors", "The phone's secure element did not sign."), QStringLiteral("tee: C_Sign: %1, %2 bytes").arg(hex(rv)).arg(raw.size())};
        return QByteArray();
    }
    return derSignature(raw);
}

PinStatus adminPin()
{
    PinStatus s;
    Token token;
    CK_TOKEN_INFO info;
    const State state = token.openAdmin(&info, &s.failure);
    if (state != State::Ready) {
        s.state = PinState::Failed;
        return s;
    }
    return statusOf(info);
}

PinResult enterAdminPin(const QByteArray &pin, PinStatus *after, Failure *failure)
{
    // A PIN set before the rule (pinrule.h) still opens the key; a new one
    // must pass it, below.
    if (pin.size() < 4 || pin.size() > 128)
        return pinFailed(failure, after, QStringLiteral("a PIN of %1 bytes").arg(pin.size()));
    QSettings settings;
    // Signing in anew ends the login kept so far.
    dropAdminPin();
    auto held = std::unique_ptr<Token>(new Token);
    Token &token = *held;
    CK_TOKEN_INFO info;
    if (token.openAdmin(&info, failure) != State::Ready) {
        after->state = PinState::Failed;
        after->failure = *failure;
        return PinResult::Failed;
    }
    CK_RV rv = CKR_OK;
    // A new PIN, for a token not made yet, passes the rule; a token made
    // halfway (stopped before its user PIN) is finished with the PIN it
    // already has as its SO PIN, which may be one from before the rule.
    if (!(info.flags & CKF_TOKEN_INITIALIZED) && !passesRule(pin))
        return pinTooSimple(failure, after);
    if (!(info.flags & CKF_TOKEN_INITIALIZED)) {
        // The first PIN: the token starts with it as its SO PIN too, so a
        // stop halfway leaves a token the same PIN finishes.
        settings.remove(soRandomKey);
        rv = token.initAdmin(pin);
        if (rv != CKR_OK)
            return pinFailed(failure, after, QStringLiteral("C_InitToken admin: %1").arg(hex(rv)));
        token.refresh(&info);
    }
    if (!(info.flags & CKF_USER_PIN_INITIALIZED)) {
        rv = token.initUserPin(pin);
        if (rv == CKR_PIN_INCORRECT) {
            token.refresh(&info);
            *after = statusOf(info);
            return PinResult::Wrong;
        }
        if (rv != CKR_OK)
            return pinFailed(failure, after, QStringLiteral("C_InitPIN admin: %1").arg(hex(rv)));
        token.refresh(&info);
    }
    if (info.flags & CKF_USER_PIN_LOCKED) {
        *after = statusOf(info);
        return PinResult::Locked;
    }
    rv = token.login(CKU_USER, pin);
    if (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED || rv == CKR_PIN_LEN_RANGE) {
        settings.setValue(wrongKey, settings.value(wrongKey).toInt() + 1);
        token.refresh(&info);
        *after = statusOf(info);
        return after->state == PinState::Locked || rv == CKR_PIN_LOCKED ? PinResult::Locked : PinResult::Wrong;
    }
    if (rv != CKR_OK)
        return pinFailed(failure, after, QStringLiteral("C_Login admin: %1").arg(hex(rv)));
    settings.remove(wrongKey);
    if (!settings.value(soRandomKey).toBool()) {
        // The SO logs in alone: the user logs out for it and back in after.
        // The note that the SO PIN is random lives in the app's settings,
        // which can be cleared while the token stays: the token decides.
        // An SO PIN that is not the user PIN (wrong, or locked by such
        // tries) was made random already, so it is noted and never tried
        // again; one that still is the user PIN is made random now, and
        // until that works the admin key is not used.
        token.logout();
        bool notSo = false;
        rv = token.randomizeSo(pin, &notSo);
        // Any other answer fails this action, with the code in the
        // details; the next action asks the token again, never a loop.
        if (rv == CKR_OK || notSo)
            settings.setValue(soRandomKey, true);
        else
            return pinFailed(failure, after, QStringLiteral("the SO PIN did not change: %1").arg(hex(rv)));
        rv = token.login(CKU_USER, pin);
        if (rv != CKR_OK)
            return pinFailed(failure, after, QStringLiteral("C_Login admin after the SO: %1").arg(hex(rv)));
    }
    token.refresh(&info);
    *after = statusOf(info);
    keep(std::move(held));
    return PinResult::Right;
}

PinResult changeAdminPin(const QByteArray &old, const QByteArray &pin, PinStatus *after, Failure *failure)
{
    if (!passesRule(pin))
        return pinTooSimple(failure, after);
    QSettings settings;
    dropAdminPin();
    auto held = std::unique_ptr<Token>(new Token);
    Token &token = *held;
    CK_TOKEN_INFO info;
    if (token.openAdmin(&info, failure) != State::Ready) {
        after->state = PinState::Failed;
        after->failure = *failure;
        return PinResult::Failed;
    }
    if (statusOf(info).state != PinState::Set) {
        *after = statusOf(info);
        return after->state == PinState::Locked ? PinResult::Locked : pinFailed(failure, after, QStringLiteral("no PIN to change"));
    }
    CK_RV rv = token.login(CKU_USER, old);
    if (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED) {
        settings.setValue(wrongKey, settings.value(wrongKey).toInt() + 1);
        token.refresh(&info);
        *after = statusOf(info);
        return after->state == PinState::Locked || rv == CKR_PIN_LOCKED ? PinResult::Locked : PinResult::Wrong;
    }
    if (rv != CKR_OK)
        return pinFailed(failure, after, QStringLiteral("C_Login admin: %1").arg(hex(rv)));
    settings.remove(wrongKey);
    if (!settings.value(soRandomKey).toBool()) {
        // As in enterAdminPin: the SO PIN is made random, or found random,
        // with the PIN it may still share, before that PIN changes.
        token.logout();
        bool notSo = false;
        rv = token.randomizeSo(old, &notSo);
        // Any other answer fails this action, with the code in the
        // details; the next action asks the token again, never a loop.
        if (rv == CKR_OK || notSo)
            settings.setValue(soRandomKey, true);
        else
            return pinFailed(failure, after, QStringLiteral("the SO PIN did not change: %1").arg(hex(rv)));
        rv = token.login(CKU_USER, old);
        if (rv != CKR_OK)
            return pinFailed(failure, after, QStringLiteral("C_Login admin after the SO: %1").arg(hex(rv)));
    }
    rv = token.setUserPin(old, pin);
    if (rv != CKR_OK)
        return pinFailed(failure, after, QStringLiteral("C_SetPIN admin: %1").arg(hex(rv)));
    token.refresh(&info);
    *after = statusOf(info);
    keep(std::move(held));
    return PinResult::Right;
}

bool adminPinHeld()
{
    // In use on another thread, which renews it: held.
    if (!keptLock.tryLock())
        return true;
    const bool alive = keptAlive();
    keptLock.unlock();
    return alive;
}

void dropAdminPin()
{
    QMutexLocker l(&keptLock);
    kept.reset();
}

bool forget(Failure *failure)
{
    {
        Token token;
        if (token.openMember(failure) != State::Ready)
            return false;
        // The admin key of an older version sat in this token too.
        for (const Which which : {Which::Member, Which::Admin}) {
            const QByteArray keyLabel = labelOf(which);
            for (const CK_ULONG cls : {CKO_PRIVATE_KEY, CKO_PUBLIC_KEY}) {
                for (const CK_OBJECT_HANDLE h : token.find(cls, keyLabel)) {
                    const CK_RV rv = token.destroy(h);
                    if (rv != CKR_OK) {
                        *failure = {QCoreApplication::translate("Errors", "The phone could not delete its key."),
                                    QStringLiteral("tee: C_DestroyObject %1: %2").arg(QLatin1String(keyLabel), hex(rv))};
                        return false;
                    }
                }
            }
        }
    }
    // The admin key goes while its login lasts; otherwise the next admin
    // key replaces it, and until then it signs nothing without the PIN.
    QSettings().setValue(staleKey, true);
    withLogin([](Token &in) {
        bool all = true;
        for (const CK_ULONG cls : {CKO_PRIVATE_KEY, CKO_PUBLIC_KEY})
            for (const CK_OBJECT_HANDLE h : in.find(cls, labelOf(Which::Admin)))
                all = in.destroy(h) == CKR_OK && all;
        if (all)
            QSettings().remove(staleKey);
    });
    return true;
}

QByteArray derSignature(const QByteArray &raw)
{
    auto integer = [](QByteArray v) {
        while (v.size() > 1 && v.at(0) == 0 && !(v.at(1) & 0x80))
            v.remove(0, 1);
        if (v.at(0) & 0x80)
            v.prepend('\0');
        return QByteArray(1, 0x02) + char(v.size()) + v;
    };
    const int half = raw.size() / 2;
    const QByteArray body = integer(raw.left(half)) + integer(raw.mid(half));
    return QByteArray(1, 0x30) + char(body.size()) + body;
}

} // namespace KeyStore
