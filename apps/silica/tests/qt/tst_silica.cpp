// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The Aurora app's code that needs no screen, on the computer with desktop
// Qt 5 and the core built for it: errors, the saved membership, the device
// events, the calls into the core and the key in a file. run.sh builds and
// runs it, with coverage when asked (docs/testing.md, "Coverage").

#include "../../src/core.h"
#include "../../src/errors.h"
#include "../../src/events.h"
#include "../../src/membership.h"
#include "../../src/platform/keystore.h"

#include <cbb_core.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QSettings>
#include <QSignalSpy>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QtTest>

namespace {

QVariantMap device(const QString &id, const QString &name, bool admin = false, bool frozen = false, bool root = false, bool self = false)
{
    return QVariantMap{{QStringLiteral("id"), id},       {QStringLiteral("name"), name},     {QStringLiteral("admin"), admin},
                       {QStringLiteral("frozen"), frozen}, {QStringLiteral("root"), root}, {QStringLiteral("self"), self}};
}

QString dataFile(const QString &name)
{
    return Membership::directory() + QLatin1Char('/') + name;
}

} // namespace

class SilicaTest : public QObject
{
    Q_OBJECT

private slots:
    void init()
    {
        QSettings().clear();
        QDir(Membership::directory()).removeRecursively();
        qunsetenv("CBB_ERROR_DETAILS");
    }

    // A failure shows its details only when they are on: the setting first,
    // then CBB_ERROR_DETAILS; the log has them either way.
    void errorsShowDetailsWhenOn()
    {
        const Failure f{QStringLiteral("It broke."), QStringLiteral("core: x\nmore")};
        QSettings().setValue(QStringLiteral("errors/details"), false);
        QCOMPARE(Errors::shown(f), QStringLiteral("It broke."));
        QSettings().setValue(QStringLiteral("errors/details"), true);
        QCOMPARE(Errors::shown(f), QStringLiteral("It broke.\n\ncore: x\nmore"));
        QCOMPARE(Errors::shown(Failure{QStringLiteral("Plain."), QString()}), QStringLiteral("Plain."));
        QSettings().remove(QStringLiteral("errors/details"));
        qputenv("CBB_ERROR_DETAILS", "0");
        QVERIFY(!Errors::showDetails());
        qputenv("CBB_ERROR_DETAILS", "1");
        QVERIFY(Errors::showDetails());
        QFile log(dataFile(QStringLiteral("cbb.log")));
        QVERIFY(log.open(QIODevice::ReadOnly));
        QVERIFY(log.readAll().contains("error: It broke.: core: x; more"));
    }

    // The log starts again past a mebibyte.
    void errorsLogStartsAgain()
    {
        Errors::log(QStringLiteral("first"));
        QFile log(dataFile(QStringLiteral("cbb.log")));
        QVERIFY(log.open(QIODevice::Append));
        log.write(QByteArray(1024 * 1024 + 1, 'x'));
        log.close();
        Errors::log(QStringLiteral("second"));
        QVERIFY(log.open(QIODevice::ReadOnly));
        const QByteArray text = log.readAll();
        QVERIFY(text.size() < 100);
        QVERIFY(text.contains("second"));
    }

    // member.json: none, saved and read back, one of a group made before
    // 0.6, one of another version, and leaving.
    void membershipSavesAndLeaves()
    {
        Failure failure;
        QVERIFY(Membership::load(&failure).isNull());
        QVERIFY(failure.isNull());

        Membership m;
        m.device = QStringLiteral("dev1");
        m.group = QStringLiteral("0123456789abcdef0123");
        m.admin = true;
        QVERIFY(m.save(&failure));
        const Membership back = Membership::load(&failure);
        QVERIFY(failure.isNull());
        QCOMPARE(back.device, m.device);
        QCOMPARE(back.groupTag(), QStringLiteral("0123456789abcdef"));
        QVERIFY(back.isAdmin() && !back.root && !back.before06 && !back.isNull());
        QCOMPARE(QFile::permissions(dataFile(QStringLiteral("member.json"))) & 0x0077, QFile::Permissions());

        m.root = true;
        m.admin = false;
        QVERIFY(m.save(&failure));
        QVERIFY(Membership::load(&failure).root);

        QFile f(dataFile(QStringLiteral("member.json")));
        QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
        f.write(R"({"v":1,"device":"old"})");
        f.close();
        const Membership old = Membership::load(&failure);
        QVERIFY(old.before06 && !old.isNull() && old.groupTag().isEmpty());

        QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
        f.write(R"({"v":2})");
        f.close();
        QVERIFY(Membership::load(&failure).isNull());
        QCOMPARE(failure.message, QStringLiteral("The phone could not read its group."));
        QVERIFY(failure.details.contains(QStringLiteral("not of version 1")));

        // Leaving takes the group's files, a folder with what it holds, and
        // member.json; the app's own files stay.
        QDir(Membership::directory()).mkpath(QStringLiteral("content/sub"));
        QFile(dataFile(QStringLiteral("content/sub/a"))).open(QIODevice::WriteOnly);
        QFile(dataFile(QStringLiteral("identity.json"))).open(QIODevice::WriteOnly);
        QFile(dataFile(QStringLiteral("seal.key"))).open(QIODevice::WriteOnly);
        QFile(dataFile(QStringLiteral("cbb.log"))).open(QIODevice::WriteOnly);
        failure = Failure();
        QVERIFY(Membership::remove(&failure));
        QVERIFY(failure.isNull());
        for (const char *gone : {"content", "identity.json", "seal.key", "member.json"})
            QVERIFY2(!QFileInfo::exists(dataFile(QString::fromLatin1(gone))), gone);
        QVERIFY(QFileInfo::exists(dataFile(QStringLiteral("cbb.log"))));
        QVERIFY(Membership::remove(&failure));
    }

    // What changed between two looks, by name, removals last.
    void eventsBetween()
    {
        const QVariantList first{device(QStringLiteral("me"), QStringLiteral("Phone"), false, false, false, true),
                                 device(QStringLiteral("a"), QStringLiteral("Anna")), device(QStringLiteral("b"), QStringLiteral("Bob"), true),
                                 device(QStringLiteral("c"), QStringLiteral("Cat")), device(QStringLiteral("a"), QStringLiteral("Twice")),
                                 device(QString(), QStringLiteral("No ID"))};
        const auto old = Events::seen(first);
        QCOMPARE(old.size(), 3);
        QCOMPARE(old.value(QStringLiteral("a")).name, QStringLiteral("Anna"));

        const QVariantList second{device(QStringLiteral("a"), QStringLiteral("Anna"), true, true), device(QStringLiteral("b"), QStringLiteral("Bob"), true, false, true),
                                  device(QStringLiteral("d"), QStringLiteral("Dan"))};
        const auto events = Events::between(old, Events::seen(second));
        QStringList got;
        for (const auto &e : events)
            got << e.kind + QLatin1Char(':') + e.text;
        QCOMPARE(got, QStringList({QStringLiteral("admins:Anna is an admin now."),
                                   QStringLiteral("frozen:Anna was frozen: the others refuse it until an admin unfreezes it."),
                                   QStringLiteral("takeover:Bob moved the group to itself: it is the group's main device now."),
                                   QStringLiteral("devices:Dan joined the group."), QStringLiteral("devices:Cat was removed from the group.")}));
        const QVariantList third{device(QStringLiteral("a"), QStringLiteral("Anna"), true, false)};
        const auto unfrozen = Events::between(Events::seen(second), Events::seen(third));
        QCOMPARE(unfrozen.first().text, QStringLiteral("Anna was unfrozen."));
    }

    // The first look only remembers; later ones post each event whose kind
    // is on, and the cover keeps the five newest.
    void eventsObserve()
    {
        Events e;
        QSignalSpy posted(&e, &Events::posted);
        QSignalSpy recent(&e, &Events::recentChanged);
        e.observe(QVariantList());
        e.observe({device(QStringLiteral("a"), QStringLiteral("Anna"))});
        QCOMPARE(posted.count(), 0);
        e.observe({device(QStringLiteral("a"), QStringLiteral("Anna"))});
        QCOMPARE(recent.count(), 0);

        QVERIFY(e.isOn(QStringLiteral("devices")));
        e.setOn(QStringLiteral("frozen"), false);
        QVERIFY(!e.isOn(QStringLiteral("frozen")));
        e.observe({device(QStringLiteral("a"), QStringLiteral("Anna"), false, true), device(QStringLiteral("b"), QStringLiteral("Bob"))});
        QCOMPARE(posted.count(), 1);
        QCOMPARE(posted.first().at(1).toString(), QStringLiteral("devices"));
        QCOMPARE(e.recent().size(), 2);

        QVariantList many;
        for (int i = 0; i < 7; ++i)
            many << device(QStringLiteral("n%1").arg(i), QStringLiteral("New %1").arg(i));
        e.observe(many);
        QCOMPARE(e.recent().size(), 5);

        e.forget();
        QVERIFY(e.recent().isEmpty());
        posted.clear();
        e.observe({device(QStringLiteral("z"), QStringLiteral("Zed"))});
        QCOMPARE(posted.count(), 0);
    }

    // The core answers its version; an unknown call and a panic come back
    // as failures with the core's details.
    void coreCalls()
    {
        Failure failure;
        const QString line = Core::versionLine(&failure);
        QVERIFY2(failure.isNull(), qPrintable(failure.details));
        QVERIFY(line.startsWith(QStringLiteral("core ")));
        QVERIFY(line.contains(QStringLiteral("abi 1")));

        QVERIFY(Core::call(QStringLiteral("no_such_call"), QJsonValue(), &failure).isNull());
        QVERIFY(!failure.isNull());
        QVERIFY(failure.details.startsWith(QStringLiteral("core: no_such_call (")));
        QVERIFY(Core::versionLine(&failure).isEmpty()); // an earlier failure stays

        failure = Failure();
        const QJsonValue code = Core::testPanic(&failure);
        QVERIFY(code.isDouble());
        QVERIFY(failure.details.startsWith(QStringLiteral("core: test_panic (")));

        failure = Failure();
        QVERIFY(Core::take(nullptr, 0, QStringLiteral("pair"), &failure).isEmpty());
        QCOMPARE(failure.details, QStringLiteral("pair: no answer"));
    }

    // take reads an answer the core made, ok or error.
    void coreTake()
    {
        const auto answer = [](const QByteArray &request, size_t *len) {
            return cbb_call(reinterpret_cast<const uint8_t *>(request.constData()), size_t(request.size()), len);
        };
        size_t len = 0;
        Failure failure;
        uint8_t *ok = answer(R"({"abi":1,"op":"version"})", &len);
        QVERIFY(!Core::take(ok, len, QStringLiteral("version"), &failure).value(QStringLiteral("core")).toString().isEmpty());
        QVERIFY(failure.isNull());
        uint8_t *bad = answer(R"({"abi":1,"op":"no_such_call"})", &len);
        QVERIFY(Core::take(bad, len, QStringLiteral("x"), &failure).isEmpty());
        QVERIFY(failure.details.startsWith(QStringLiteral("x: ")));
    }

    // The key in a file: made once, read back, signing a digest through the
    // core, and forgotten.
    void fileKeySigns()
    {
        QCOMPARE(KeyStore::store(), QStringLiteral("file"));
        uint8_t sig[72];
        size_t sigLen = 0;
        const uint8_t digest[32] = {1, 2, 3};
        Failure failure;
        QVERIFY(KeyStore::sign(QByteArray(32, 1), &failure).isEmpty());
        QCOMPARE(failure.details, QStringLiteral("key: sign before ensure"));
        QCOMPARE(Core::signDigest(nullptr, digest, sig, &sigLen), 1);

        const KeyStore::Key made = KeyStore::ensure();
        QVERIFY2(made.state == KeyStore::State::Ready, qPrintable(made.failure.details));
        QVERIFY(made.created);
        QCOMPARE(made.publicKey.size(), 65);
        const KeyStore::Key again = KeyStore::ensure();
        QVERIFY(!again.created && again.publicKey == made.publicKey);
        QCOMPARE(Core::signDigest(nullptr, digest, sig, &sigLen), 0);
        QVERIFY(sigLen > 8 && sigLen <= 72 && sig[0] == 0x30);

        Core::AdminSign admin;
        QCOMPARE(Core::signAdminDigest(&admin, digest, sig, &sigLen), 1); // no admin key yet
        QVERIFY(KeyStore::ensure(KeyStore::Which::Admin).state == KeyStore::State::Ready);
        QCOMPARE(Core::signAdminDigest(&admin, digest, sig, &sigLen), 0);
        QVERIFY(!admin.pinNeeded);

        KeyStore::PinStatus after;
        QVERIFY(KeyStore::adminPin().state == KeyStore::PinState::None);
        QVERIFY(KeyStore::enterAdminPin("1", &after, &failure) == KeyStore::PinResult::Right);
        QVERIFY(KeyStore::changeAdminPin("1", "2", &after, &failure) == KeyStore::PinResult::Right);
        QVERIFY(KeyStore::adminPinHeld());
        KeyStore::dropAdminPin();

        QFile damaged(dataFile(QStringLiteral("admin.key")));
        QVERIFY(damaged.open(QIODevice::WriteOnly | QIODevice::Truncate));
        damaged.write("{}");
        damaged.close();
        QCOMPARE(KeyStore::ensure(KeyStore::Which::Admin).failure.message, QStringLiteral("The phone's key file is damaged."));

        failure = Failure();
        QVERIFY(KeyStore::forget(&failure));
        QVERIFY(!QFileInfo::exists(dataFile(QStringLiteral("device.key"))));
        QCOMPARE(Core::signDigest(nullptr, digest, sig, &sigLen), 1);
    }
};

int main(int argc, char **argv)
{
    // Everything the app writes goes into a folder of its own.
    QTemporaryDir home;
    qputenv("HOME", home.path().toLocal8Bit());
    qputenv("XDG_DATA_HOME", (home.path() + QStringLiteral("/data")).toLocal8Bit());
    qputenv("XDG_CONFIG_HOME", (home.path() + QStringLiteral("/config")).toLocal8Bit());
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("cbb"));
    QCoreApplication::setApplicationName(QStringLiteral("test"));
    SilicaTest t;
    return QTest::qExec(&t, argc, argv);
}

#include "tst_silica.moc"
