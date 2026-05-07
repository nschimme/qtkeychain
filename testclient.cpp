/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include <QtGlobal>
#ifdef Q_OS_DARWIN
#  include <QGuiApplication>
#else
#  include <QCoreApplication>
#endif

#include <QStringList>

#include "qtkeychain/keychain.h"
#include <iostream>

using namespace QKeychain;

static int printUsage()
{
    std::cerr << "testclient store <account> <password> [--security-level standard|biometric]" << std::endl;
    std::cerr << "testclient bstore <account> <password> [--security-level standard|biometric]" << std::endl;
    std::cerr << "testclient restore <account> [--security-level standard|biometric]" << std::endl;
    std::cerr << "testclient delete <account> [--security-level standard|biometric]" << std::endl;
    return 1;
}

int main(int argc, char **argv)
{
#ifdef Q_OS_DARWIN
    // Since we use NSNotificationCenter under the hood in keychain_apple,
    // we use QGuiApplication to automatically configure the platform
    // integration stuff done in this class and not in QCoreApplication
    QGuiApplication app(argc, argv);
#else
    QCoreApplication app(argc, argv);
#endif
    const QStringList args = app.arguments();
    if (args.count() < 2)
        return printUsage();

    QStringList::ConstIterator it = args.constBegin();
    ++it;

    if (*it == QLatin1String("store")) {
        if (++it == args.constEnd())
            return printUsage();
        const QString acc = *it;
        if (++it == args.constEnd())
            return printUsage();
        const QString pass = *it;

        Job::SecurityLevel securityLevel = Job::Standard;
        if (++it != args.constEnd()) {
            if (*it == QLatin1String("--security-level")) {
                if (++it == args.constEnd())
                    return printUsage();
                if (*it == QLatin1String("standard")) {
                    securityLevel = Job::Standard;
                } else if (*it == QLatin1String("biometric")) {
                    securityLevel = Job::Biometric;
                } else {
                    return printUsage();
                }
                ++it;
            }
        }

        if (it != args.constEnd())
            return printUsage();

        WritePasswordJob job(QLatin1String("qtkeychain-testclient"));
        job.setAutoDelete(false);
        job.setKey(acc);
        job.setTextData(pass);
        job.setSecurityLevel(securityLevel);
        QEventLoop loop;
        job.connect(&job, &Job::finished, &loop, &QEventLoop::quit);
        job.start();
        loop.exec();
        if (job.error()) {
            std::cerr << "Storing password failed: " << qPrintable(job.errorString()) << std::endl;
            return 1;
        }
        std::cout << "Password stored successfully" << std::endl;
    } else if (*it == QLatin1String("bstore")) {
        if (++it == args.constEnd())
            return printUsage();
        const QString acc = *it;
        if (++it == args.constEnd())
            return printUsage();
        const QString pass = *it;

        Job::SecurityLevel securityLevel = Job::Standard;
        if (++it != args.constEnd()) {
            if (*it == QLatin1String("--security-level")) {
                if (++it == args.constEnd())
                    return printUsage();
                if (*it == QLatin1String("standard")) {
                    securityLevel = Job::Standard;
                } else if (*it == QLatin1String("biometric")) {
                    securityLevel = Job::Biometric;
                } else {
                    return printUsage();
                }
                ++it;
            }
        }

        if (it != args.constEnd())
            return printUsage();

        WritePasswordJob job(QLatin1String("qtkeychain-testclient"));
        job.setAutoDelete(false);
        job.setKey(acc);
        job.setBinaryData(pass.toUtf8());
        job.setSecurityLevel(securityLevel);
        QEventLoop loop;
        job.connect(&job, &Job::finished, &loop, &QEventLoop::quit);
        job.start();
        loop.exec();
        if (job.error()) {
            std::cerr << "Storing binary password failed: " << qPrintable(job.errorString())
                      << std::endl;
            return 1;
        }
        std::cout << "Password stored successfully" << std::endl;
    } else if (*it == QLatin1String("restore")) {
        if (++it == args.constEnd())
            return printUsage();
        const QString acc = *it;

        Job::SecurityLevel securityLevel = Job::Standard;
        bool securityLevelSet = false;
        if (++it != args.constEnd()) {
            if (*it == QLatin1String("--security-level")) {
                if (++it == args.constEnd())
                    return printUsage();
                if (*it == QLatin1String("standard")) {
                    securityLevel = Job::Standard;
                } else if (*it == QLatin1String("biometric")) {
                    securityLevel = Job::Biometric;
                } else {
                    return printUsage();
                }
                securityLevelSet = true;
                ++it;
            }
        }

        if (it != args.constEnd())
            return printUsage();

        ReadPasswordJob job(QLatin1String("qtkeychain-testclient"));
        job.setAutoDelete(false);
        job.setKey(acc);
        if (securityLevelSet) {
            job.setSecurityLevel(securityLevel);
        }
        QEventLoop loop;
        job.connect(&job, &Job::finished, &loop, &QEventLoop::quit);
        job.start();
        loop.exec();

        const QString pw = job.textData();
        if (job.error()) {
            std::cerr << "Restoring password failed: " << qPrintable(job.errorString())
                      << std::endl;
            return 1;
        }
        std::cout << qPrintable(pw) << std::endl;
    } else if (*it == QLatin1String("delete")) {
        if (++it == args.constEnd())
            return printUsage();
        const QString acc = *it;

        Job::SecurityLevel securityLevel = Job::Standard;
        bool securityLevelSet = false;
        if (++it != args.constEnd()) {
            if (*it == QLatin1String("--security-level")) {
                if (++it == args.constEnd())
                    return printUsage();
                if (*it == QLatin1String("standard")) {
                    securityLevel = Job::Standard;
                } else if (*it == QLatin1String("biometric")) {
                    securityLevel = Job::Biometric;
                } else {
                    return printUsage();
                }
                securityLevelSet = true;
                ++it;
            }
        }

        if (it != args.constEnd())
            return printUsage();

        DeletePasswordJob job(QLatin1String("qtkeychain-testclient"));
        job.setAutoDelete(false);
        job.setKey(acc);
        if (securityLevelSet) {
            job.setSecurityLevel(securityLevel);
        }
        QEventLoop loop;
        job.connect(&job, &Job::finished, &loop, &QEventLoop::quit);
        job.start();
        loop.exec();

        if (job.error()) {
            std::cerr << "Deleting password failed: " << qPrintable(job.errorString()) << std::endl;
            return 1;
        }
        std::cout << "Password deleted successfully" << std::endl;
    } else {
        return printUsage();
    }
}
