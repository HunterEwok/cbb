// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "keystore.h"

#include "pkcs11.h"
#include "qcainit.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QVector>

#include <dlfcn.h>
#include <cstring>

using namespace pkcs11;

namespace KeyStore {

namespace {

// The labels of the key's two halves.
const QByteArray keyLabel("cbb-member");

QString hex(CK_RV rv) { return QStringLiteral("0x%1").arg(rv, 0, 16); }

QString fixed(const unsigned char *s, int n)
{
    // Token labels are padded with spaces or, from QCA, with NUL bytes.
    int len = n;
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\0'))
        --len;
    return QString::fromLatin1(reinterpret_cast<const char *>(s), len);
}

// A logged-in session in the app's token, closed when it goes out of scope.
class Token
{
public:
    ~Token()
    {
        if (m_session)
            m_f->C_CloseSession(m_session);
        if (m_f)
            m_f->C_Finalize(nullptr);
        if (m_lib)
            dlclose(m_lib);
    }

    // Opens libckteec and finds the token QCA initialized for this app, the
    // first time initializing it. state is NoTee without OP-TEE.
    State open(Failure *failure)
    {
        if (!QFile::exists(QStringLiteral("/dev/tee0"))) {
            *failure = {QCoreApplication::translate("Errors", "This phone has no secure element for keys."), QStringLiteral("tee: no /dev/tee0")};
            return State::NoTee;
        }
        m_lib = dlopen("libckteec.so.0", RTLD_NOW);
        if (!m_lib) {
            *failure = {QCoreApplication::translate("Errors", "This phone has no secure element for keys."),
                        QStringLiteral("tee: %1").arg(QString::fromLocal8Bit(dlerror()))};
            return State::NoTee;
        }
        auto getList = reinterpret_cast<CK_RV (*)(CK_FUNCTION_LIST **)>(dlsym(m_lib, "C_GetFunctionList"));
        CK_FUNCTION_LIST *f = nullptr;
        CK_RV rv = getList ? getList(&f) : CK_RV(~0ul);
        if (rv != CKR_OK || !f)
            return fail(failure, QStringLiteral("C_GetFunctionList: %1").arg(hex(rv)));
        rv = f->C_Initialize(nullptr);
        if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
            return fail(failure, QStringLiteral("C_Initialize: %1").arg(hex(rv)));
        m_f = f;

        CK_SLOT_ID slot = 0;
        CK_TOKEN_INFO info;
        if (!findToken(&slot, &info)) {
            // Never initialized: the first run after the app was installed.
            // QCA's plugin opens libckteec in this process too, so the app
            // lets go of it until QCA is done.
            m_f->C_Finalize(nullptr);
            m_f = nullptr;
            const Failure qca = QcaInit::initUserAppKeystore();
            if (!qca.isNull()) {
                *failure = qca;
                return State::Failed;
            }
            rv = f->C_Initialize(nullptr);
            if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
                return fail(failure, QStringLiteral("C_Initialize after QCA: %1").arg(hex(rv)));
            m_f = f;
            if (!findToken(&slot, &info))
                return fail(failure, QStringLiteral("no token \"%1\" after QCA initialized USERAPP").arg(QLatin1String(QcaInit::tokenLabel)));
        }
        const QString model = fixed(info.model, 16);
        if (model != QLatin1String("Aurora TA"))
            return fail(failure, QStringLiteral("the token's model is \"%1\", not Aurora TA").arg(model));

        rv = m_f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &m_session);
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
        }
        return State::Ready;
    }

    QVector<CK_OBJECT_HANDLE> find(CK_ULONG cls)
    {
        QByteArray label = keyLabel;
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

    CK_RV generate(CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
    {
        CK_BBOOL yes = 1, no = 0;
        QByteArray label = keyLabel;
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

private:
    State fail(Failure *failure, const QString &why)
    {
        *failure = {QCoreApplication::translate("Errors", "The phone's secure element did not answer."), QStringLiteral("tee: ") + why};
        return State::Failed;
    }

    bool findToken(CK_SLOT_ID *slot, CK_TOKEN_INFO *info)
    {
        CK_ULONG count = 0;
        if (m_f->C_GetSlotList(1, nullptr, &count) != CKR_OK || count == 0)
            return false;
        QVector<CK_SLOT_ID> slotIds(static_cast<int>(count));
        if (m_f->C_GetSlotList(1, slotIds.data(), &count) != CKR_OK)
            return false;
        for (CK_ULONG i = 0; i < count; ++i) {
            CK_TOKEN_INFO t;
            std::memset(&t, 0, sizeof t);
            if (m_f->C_GetTokenInfo(slotIds[int(i)], &t) != CKR_OK || !(t.flags & CKF_TOKEN_INITIALIZED))
                continue;
            if (fixed(t.label, 32) == QLatin1String(QcaInit::tokenLabel)) {
                *slot = slotIds[int(i)];
                *info = t;
                return true;
            }
        }
        return false;
    }

    void *m_lib = nullptr;
    CK_FUNCTION_LIST *m_f = nullptr;
    CK_SESSION_HANDLE m_session = 0;
};

} // namespace

QString store()
{
    return QStringLiteral("hardware");
}

Key ensure()
{
    Key key;
    Token token;
    key.state = token.open(&key.failure);
    if (key.state != State::Ready)
        return key;

    const QVector<CK_OBJECT_HANDLE> privs = token.find(CKO_PRIVATE_KEY), pubs = token.find(CKO_PUBLIC_KEY);
    CK_OBJECT_HANDLE priv = 0, pub = 0;
    if (privs.size() == 1 && pubs.size() == 1) {
        priv = privs.first();
        pub = pubs.first();
    } else if (privs.isEmpty() && pubs.isEmpty()) {
        const CK_RV rv = token.generate(&pub, &priv);
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

QByteArray sign(const QByteArray &digest, Failure *failure)
{
    Token token;
    if (token.open(failure) != State::Ready)
        return QByteArray();
    const QVector<CK_OBJECT_HANDLE> privs = token.find(CKO_PRIVATE_KEY);
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
