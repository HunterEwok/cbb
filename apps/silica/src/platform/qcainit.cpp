// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#include "qcainit.h"

#include <QtCrypto>

#include <QSemaphore>
#include <QThread>

namespace QcaInit {

const char tokenLabel[] = "CBB";
const char pin[] = "0000";

namespace {

// Answers the plugin's questions: the keystore, its name, the PKCS#11
// provider of OP-TEE ("cktee") and the PIN. Anything else is refused.
class Asker : public QObject
{
public:
    Asker()
    {
        connect(&m_handler, &QCA::EventHandler::eventReady, this, [this](int id, const QCA::Event &e) {
            switch (e.type()) {
            case QCA::Event::Password:
                m_handler.submitPassword(id, QCA::SecureArray(pin));
                break;
            case QCA::Event::KeyStoreId:
                m_handler.submitKeyStoreId(id, QStringLiteral("USERAPP"));
                break;
            case QCA::Event::KeyStoreName:
                m_handler.submitKeyStoreName(id, QString::fromLatin1(tokenLabel));
                break;
            case QCA::Event::KeyStorePkcs11Provider:
                m_handler.submitKeyStorePkcs11Provider(id, QStringLiteral("cktee"));
                break;
            default:
                Errors::log(QStringLiteral("qca: question %1 not expected, refused").arg(e.type()));
                m_handler.reject(id);
            }
        });
        m_handler.start();
    }

private:
    QCA::EventHandler m_handler;
};

// The asker lives in a thread of its own with an event loop, since the
// plugin's calls block the thread that makes them.
class AskerThread : public QThread
{
public:
    QSemaphore ready;

protected:
    void run() override
    {
        Asker asker;
        ready.release();
        exec();
    }
};

} // namespace

Failure initUserAppKeystore()
{
    QCA::Initializer init;
    AskerThread asker;
    asker.start();
    asker.ready.acquire();

    QCA::KeyStoreManager::start(QStringLiteral("qca-aurora-pkcs11"));
    Failure failure;
    {
        QCA::KeyStoreManager ksm;
        ksm.waitForBusyFinished();
        ksm.sync();
        if (!ksm.keyStores().contains(QStringLiteral("USERAPP"))) {
            failure = {QStringLiteral("This phone keeps no keys for apps."),
                       QStringLiteral("qca: no keystore USERAPP; keystores: %1").arg(ksm.keyStores().join(QLatin1Char(' ')))};
        } else {
            const QString got = ksm.initKeyStore(QStringLiteral("USERAPP"));
            ksm.waitForBusyFinished();
            ksm.sync();
            Errors::log(QStringLiteral("qca: initKeyStore USERAPP returned \"%1\"").arg(got));
        }
    }
    asker.quit();
    asker.wait();
    return failure;
}

} // namespace QcaInit
