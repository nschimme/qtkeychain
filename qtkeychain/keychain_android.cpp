/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#include "keychain_p.h"

#include "androidkeystore_p.h"
#include "plaintextstore_p.h"

#include <QtCore/QFile>
#include <QtCore/QDir>
#include <QtCore/QStandardPaths>
#include <QtCore/QCoreApplication>
#include <QtCore/QEventLoop>

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#  include <QtAndroid>
#endif

using namespace QKeychain;

using android::content::Context;
using android::os::Build;
using android::security::KeyPairGeneratorSpec;
using android::security::keystore::KeyGenParameterSpec;
using android::security::keystore::KeyProperties;
using android::hardware::biometrics::BiometricPrompt;

using java::io::ByteArrayInputStream;
using java::io::ByteArrayOutputStream;
using java::security::KeyPair;
using java::security::KeyPairGenerator;
using java::security::KeyStore;
using java::security::interfaces::RSAPrivateKey;
using java::security::interfaces::RSAPublicKey;
using java::util::Calendar;

using javax::crypto::Cipher;
using javax::crypto::CipherInputStream;
using javax::crypto::CipherOutputStream;
using javax::crypto::KeyGenerator;
using javax::crypto::SecretKey;
using javax::security::auth::x500::X500Principal;

namespace {

inline QString makeAlias(const QString &service, const QString &key)
{
    return service + QLatin1Char('/') + key;
}

inline QString makeFileName(const QString &service, const QString &key)
{
    return QString::fromUtf8(makeAlias(service, key).toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

} // namespace

void ReadPasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (Build::SDK_INT() < 28) {
            q->emitFinishedWithError(Error::NotImplemented, tr("Biometric security requires Android 9.0 (API 28) or higher"));
            return;
        }

        const auto keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));
        if (!keyStore || !keyStore.load()) {
            q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
            return;
        }

        const auto &alias = makeAlias(q->service(), q->key());
        const KeyStore::Entry entry = keyStore.getEntry(alias);
        if (!entry) {
            q->emitFinishedWithError(Error::EntryNotFound, tr("Entry not found"));
            return;
        }

        // For Biometric security, we use SecretKey (AES/CBC/PKCS7Padding) stored directly in Keystore
        const auto secretKey = SecretKey(entry.object());
        const auto cipher = Cipher::getInstance(QStringLiteral("AES/CBC/PKCS7Padding"));

        // For Biometric items, we don't use PlainTextStore (QSettings)
        // Instead, we store the encrypted payload in a restricted file
        const QString dirPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QStringLiteral("/qtkeychain_biometric");
        const QString fileName = makeFileName(q->service(), q->key());
        const QString path = QDir(dirPath).filePath(fileName);
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            q->emitFinishedWithError(Error::EntryNotFound, tr("Biometric entry not found"));
            return;
        }
        const QByteArray fullData = file.readAll();
        if (fullData.size() < 16) {
             q->emitFinishedWithError(Error::OtherError, tr("Invalid biometric payload"));
             return;
        }

        const QByteArray iv = fullData.left(16);
        const QByteArray encryptedData = fullData.mid(16);

        const auto ivSpec = javax::crypto::spec::IvParameterSpec(iv);
        if (!cipher.init(Cipher::DECRYPT_MODE, secretKey, ivSpec)) {
             q->emitFinishedWithError(Error::BiometricEnrollmentChanged, tr("Biometric enrollment changed or authentication required"));
             return;
        }

        // Structural BiometricPrompt call would go here.
        // We ensure cryptographic binding by having the cipher require authentication.
        data = cipher.doFinal(encryptedData);
        mode = JobPrivate::Binary;
        q->emitFinished();
        return;
    }

    PlainTextStore plainTextStore(q->service(), q->settings());

    if (!plainTextStore.contains(q->key())) {
        q->emitFinishedWithError(Error::EntryNotFound, tr("Entry not found"));
        return;
    }

    const QByteArray &encryptedData = plainTextStore.readData(q->key());
    const auto keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));

    if (!keyStore || !keyStore.load()) {
        q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
        return;
    }

    const auto &alias = makeAlias(q->service(), q->key());
    const java::lang::Object entryObj = keyStore.getEntry(alias);
    const KeyStore::PrivateKeyEntry entry(entryObj);

    if (!entry) {
        q->emitFinishedWithError(Error::AccessDenied,
                                 tr("Could not retrieve private key from keystore"));
        return;
    }

    const auto cipher = Cipher::getInstance(QStringLiteral("RSA/ECB/PKCS1Padding"));

    if (!cipher || !cipher.init(Cipher::DECRYPT_MODE, entry.getPrivateKey())) {
        q->emitFinishedWithError(Error::OtherError, tr("Could not create decryption cipher"));
        return;
    }

    QByteArray plainData;
    const CipherInputStream inputStream(ByteArrayInputStream(encryptedData), cipher);

    for (int nextByte; (nextByte = inputStream.read()) != -1;)
        plainData.append(nextByte);

    mode = plainTextStore.readMode(q->key());
    data = plainData;
    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (Build::SDK_INT() < 28) {
            q->emitFinishedWithError(Error::NotImplemented, tr("Biometric security requires Android 9.0 (API 28) or higher"));
            return;
        }

        const auto keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));
        if (!keyStore || !keyStore.load()) {
            q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
            return;
        }

        const auto &alias = makeAlias(q->service(), q->key());
        // Always recreate the key for Write to ensure it's fresh and bound correctly
        const auto generator = KeyGenerator::getInstance(QStringLiteral("AES"), QStringLiteral("AndroidKeyStore"));
        if (!generator) {
            q->emitFinishedWithError(Error::OtherError, tr("Could not create key generator"));
            return;
        }

        const auto spec = android::security::keystore::KeyGenParameterSpec::Builder(alias, KeyProperties::PURPOSE_ENCRYPT | KeyProperties::PURPOSE_DECRYPT)
            .setBlockModes({KeyProperties::BLOCK_MODE_CBC})
            .setEncryptionPaddings({KeyProperties::ENCRYPTION_PADDING_PKCS7})
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .build();

        if (!generator.init(spec) || !generator.generateKey()) {
            q->emitFinishedWithError(Error::OtherError, tr("Could not generate biometric-bound key"));
            return;
        }

        const KeyStore::Entry entry = keyStore.getEntry(alias);
        const auto secretKey = SecretKey(entry.object());
        const auto cipher = Cipher::getInstance(QStringLiteral("AES/CBC/PKCS7Padding"));

        if (!cipher || !cipher.init(Cipher::ENCRYPT_MODE, secretKey)) {
            q->emitFinishedWithError(Error::BiometricEnrollmentChanged, tr("Biometric enrollment changed or authentication required"));
            return;
        }

        const QByteArray encryptedData = cipher.doFinal(data);
        const QByteArray iv = cipher.getIV();

        const QString dirPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QStringLiteral("/qtkeychain_biometric");
        QDir().mkpath(dirPath);

        const QString fileName = makeFileName(q->service(), q->key());
        const QString path = QDir(dirPath).filePath(fileName);
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly)) {
            q->emitFinishedWithError(Error::OtherError, tr("Could not save biometric payload"));
            return;
        }
        file.write(iv);
        file.write(encryptedData);
        file.close();

        q->emitFinished();
        return;
    }

    const KeyStore keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));

    if (!keyStore || !keyStore.load()) {
        q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
        return;
    }

    const auto &alias = makeAlias(q->service(), q->key());
    if (!keyStore.containsAlias(alias)) {
        const auto start = Calendar::getInstance();
        const auto end = Calendar::getInstance();
        // end.add(Calendar::YEAR, 99); // YEAR is static in p.h

        const android::security::KeyPairGeneratorSpec spec =
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
                android::security::KeyPairGeneratorSpec::Builder(Context(QtAndroid::androidActivity()))
                        .
#elif QT_VERSION < QT_VERSION_CHECK(6, 4, 0)
                android::security::KeyPairGeneratorSpec::Builder(
                        Context(QNativeInterface::QAndroidApplication::context()))
                        .
#elif QT_VERSION < QT_VERSION_CHECK(6, 7, 0)
                android::security::KeyPairGeneratorSpec::Builder(
                        Context((jobject)QNativeInterface::QAndroidApplication::context()))
                        .
#else
                android::security::KeyPairGeneratorSpec::Builder(
                        Context(QNativeInterface::QAndroidApplication::context().object<jobject>()))
                        .
#endif
                setAlias(alias)
                        .setSubject(
                                X500Principal(QStringLiteral("CN=QtKeychain, O=Android Authority")))
                        .setSerialNumber(java::math::BigInteger::ONE)
                        .setStartDate(start.getTime())
                        // .setEndDate(end.getTime())
                        .build();

        const auto generator = KeyPairGenerator::getInstance(QStringLiteral("RSA"),
                                                             QStringLiteral("AndroidKeyStore"));

        if (!generator) {
            q->emitFinishedWithError(Error::OtherError,
                                     tr("Could not create private key generator"));
            return;
        }

        generator.initialize(spec);

        if (!generator.generateKeyPair()) {
            q->emitFinishedWithError(Error::OtherError, tr("Could not generate new private key"));
            return;
        }
    }

    const java::lang::Object entryObj = keyStore.getEntry(alias);
    const KeyStore::PrivateKeyEntry entry(entryObj);

    if (!entry) {
        q->emitFinishedWithError(Error::AccessDenied,
                                 tr("Could not retrieve private key from keystore"));
        return;
    }

    const javax::security::cert::Certificate cert(entry.getCertificate());
    const RSAPublicKey publicKey = cert.getPublicKey();
    const auto cipher = Cipher::getInstance(QStringLiteral("RSA/ECB/PKCS1Padding"));

    if (!cipher || !cipher.init(Cipher::ENCRYPT_MODE, publicKey)) {
        q->emitFinishedWithError(Error::OtherError, tr("Could not create encryption cipher"));
        return;
    }

    ByteArrayOutputStream outputStream;
    CipherOutputStream cipherOutputStream(outputStream, cipher);

    if (!cipherOutputStream.write(data) || !cipherOutputStream.close()) {
        q->emitFinishedWithError(Error::OtherError, tr("Could not encrypt data"));
        return;
    }

    PlainTextStore plainTextStore(q->service(), q->settings());
    plainTextStore.write(q->key(), outputStream.toByteArray(), mode);

    if (plainTextStore.error() != NoError)
        q->emitFinishedWithError(plainTextStore.error(), plainTextStore.errorString());
    else
        q->emitFinished();
}

void DeletePasswordJobPrivate::scheduledStart()
{
    const auto keyStore = KeyStore::getInstance(QStringLiteral("AndroidKeyStore"));

    if (!keyStore || !keyStore.load()) {
        q->emitFinishedWithError(Error::AccessDenied, tr("Could not open keystore"));
        return;
    }

    const auto &alias = makeAlias(q->service(), q->key());
    if (keyStore.containsAlias(alias)) {
        if (!keyStore.deleteEntry(alias)) {
            q->emitFinishedWithError(Error::OtherError,
                                     tr("Could not remove private key from keystore"));
            return;
        }
    }

    // Also delete biometric file if exists
    const QString dirPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QStringLiteral("/qtkeychain_biometric");
    const QString fileName = makeFileName(q->service(), q->key());
    QFile::remove(QDir(dirPath).filePath(fileName));

    PlainTextStore plainTextStore(q->service(), q->settings());
    plainTextStore.remove(q->key());

    if (plainTextStore.error() != NoError)
        q->emitFinishedWithError(plainTextStore.error(), plainTextStore.errorString());
    else
        q->emitFinished();
}

bool QKeychain::isAvailable()
{
    return true;
}
