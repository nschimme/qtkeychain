#include <QCoreApplication>
#include <QDebug>
#include <keychain.h>

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const QString service = "WasmTestService";
    const QString user = "testuser";
    const QString password = "securepassword123";

    auto writeJob = new QKeychain::WritePasswordJob(service);
    writeJob->setKey(user);
    writeJob->setTextData(password);

    QObject::connect(writeJob, &QKeychain::WritePasswordJob::finished, [service, user]() {
        qDebug() << "Write job finished for" << service << user;

        auto readJob = new QKeychain::ReadPasswordJob(service);
        readJob->setKey(user);
        QObject::connect(readJob, &QKeychain::ReadPasswordJob::finished, [readJob]() {
            if (readJob->error()) {
                qDebug() << "Read job failed:" << readJob->errorString();
            } else {
                qDebug() << "Read job successful! Password:" << readJob->textData();
            }
            QCoreApplication::exit();
        });
        readJob->start();
    });

    writeJob->start();

    return app.exec();
}
