/******************************************************************************
 *   Copyright (C) 2024 Jules Software Engineer <jules@example.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include <QCoreApplication>
#include <QTimer>
#include <iostream>

#include <qtkeychain/keychain.h>

class TestRunner : public QObject
{
    Q_OBJECT

public:
    TestRunner();

public Q_SLOTS:
    void start();

private Q_SLOTS:
    void onWriteFinished(QKeychain::Job*);
    void onReadFinished(QKeychain::Job*);
    void onDeleteFinished(QKeychain::Job*);

private:
    void fail(const QString& message);
    void succeed();

    QString m_key = "test-key";
    QString m_data = "test-password";
    QString m_service = "wasm-test-app";
};

TestRunner::TestRunner()
{
    QTimer::singleShot(0, this, &TestRunner::start);
}

void TestRunner::fail(const QString& message)
{
    std::cerr << "TESTS FAILED: " << message.toStdString() << std::endl;
    QCoreApplication::exit(1);
}

void TestRunner::succeed()
{
    std::cout << "TESTS PASSED" << std::endl;
    QCoreApplication::exit(0);
}

void TestRunner::start()
{
    auto* writeJob = new QKeychain::WritePasswordJob(m_service, this);
    writeJob->setKey(m_key);
    writeJob->setTextData(m_data);
    connect(writeJob, &QKeychain::Job::finished, this, &TestRunner::onWriteFinished);
    writeJob->start();
}

void TestRunner::onWriteFinished(QKeychain::Job* job)
{
    if (job->error()) {
        fail(QString("Write operation failed: %1").arg(job->errorString()));
        return;
    }
    job->deleteLater();

    auto* readJob = new QKeychain::ReadPasswordJob(m_service, this);
    readJob->setKey(m_key);
    connect(readJob, &QKeychain::Job::finished, this, &TestRunner::onReadFinished);
    readJob->start();
}

void TestRunner::onReadFinished(QKeychain::Job* job)
{
    if (job->error()) {
        fail(QString("Read operation failed: %1").arg(job->errorString()));
        return;
    }
    if (static_cast<QKeychain::ReadPasswordJob*>(job)->textData() != m_data) {
        fail("Read data does not match written data.");
        return;
    }
    job->deleteLater();

    auto* deleteJob = new QKeychain::DeletePasswordJob(m_service, this);
    deleteJob->setKey(m_key);
    connect(deleteJob, &QKeychain::Job::finished, this, &TestRunner::onDeleteFinished);
    deleteJob->start();
}

void TestRunner::onDeleteFinished(QKeychain::Job* job)
{
    if (job->error() != QKeychain::NotImplemented) {
        fail(QString("Delete operation should have failed with NotImplemented, but got error: %1").arg(job->error()));
        return;
    }
    job->deleteLater();

    succeed();
}


int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    TestRunner runner;
    return QCoreApplication::exec();
}

#include "main.moc"
