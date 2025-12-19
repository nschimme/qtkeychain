/******************************************************************************
 *   Copyright (C) 2024 Jules Software Engineer <jules@example.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include <QCoreApplication>
#include <QTest>
#include <QTimer>

#include <qtkeychain/keychain.h>

class WasmTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testWriteRead_data();
    void testWriteRead();
    void testDelete();
};

void WasmTest::testWriteRead_data()
{
    QTest::addColumn<QString>("key");
    QTest::addColumn<QString>("data");

    QTest::newRow("simple") << "service" << "password";
    QTest::newRow("empty data") << "service" << "";
    QTest::newRow("empty key") << "" << "password";
}

void WasmTest::testWriteRead()
{
    QFETCH(QString, key);
    QFETCH(QString, data);

    // Write password
    QKeychain::WritePasswordJob writeJob("WasmTest", this);
    writeJob.setKey(key);
    writeJob.setTextData(data);
    QEventLoop writeLoop;
    connect(&writeJob, &QKeychain::Job::finished, &writeLoop, &QEventLoop::quit);
    writeJob.start();
    writeLoop.exec();

    QCOMPARE(writeJob.error(), QKeychain::NoError);

    // Read password
    QKeychain::ReadPasswordJob readJob("WasmTest", this);
    readJob.setKey(key);
    QEventLoop readLoop;
    connect(&readJob, &QKeychain::Job::finished, &readLoop, &QEventLoop::quit);
    readJob.start();
    readLoop.exec();

    QCOMPARE(readJob.error(), QKeychain::NoError);
    QCOMPARE(readJob.textData(), data);
}

void WasmTest::testDelete()
{
    QKeychain::DeletePasswordJob deleteJob("WasmTest", this);
    deleteJob.setKey("someKey");
    QEventLoop loop;
    connect(&deleteJob, &QKeychain::Job::finished, &loop, &QEventLoop::quit);
    deleteJob.start();
    loop.exec();

    QCOMPARE(deleteJob.error(), QKeychain::NotImplemented);
}

QTEST_GUILESS_MAIN(WasmTest)
#include "tst_wasm.moc"
