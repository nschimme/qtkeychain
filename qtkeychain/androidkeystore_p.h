/******************************************************************************
 *   Copyright (C) 2016 Mathias Hasselmann <mathias.hasselmann@kdab.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/

#ifndef QTKEYCHAIN_ANDROIDKEYSTORE_P_H
#define QTKEYCHAIN_ANDROIDKEYSTORE_P_H

#include <QtGlobal>

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#  include <QAndroidJniObject>
#  include <QAndroidJniEnvironment>
typedef QAndroidJniObject QJniObject;
typedef QAndroidJniEnvironment QJniEnvironment;
#else
#  include <QJniObject>
#  include <QJniEnvironment>
#endif

namespace QKeychain {

namespace java {
namespace lang {

class Object : public QJniObject
{
public:
    inline Object(jobject object = nullptr) : QJniObject(object) { }
    inline Object(const QJniObject &object) : QJniObject(object) { }
    inline operator bool() const { return isValid(); }

protected:
    static bool handleExceptions();
    template <typename T> static T handleExceptions(const T &result, const T &resultOnError = T());
};

template <typename T>
inline T Object::handleExceptions(const T &result, const T &resultOnError)
{
    if (!handleExceptions())
        return resultOnError;
    return result;
}

} // namespace lang

namespace util {
class Date : public lang::Object { public: using Object::Object; };
class Calendar : public lang::Object {
public:
    public: using Object::Object;
    static const int YEAR;
    static Calendar getInstance();
    bool add(int field, int amount) const;
    lang::Object getTime() const;
};
namespace concurrent {
class Executor : public lang::Object { public: using Object::Object; };
} // namespace concurrent
} // namespace util

namespace math {
class BigInteger : public lang::Object {
public:
    using Object::Object;
    static const BigInteger ONE;
};
} // namespace math

namespace security {
namespace spec {
class AlgorithmParameterSpec : public lang::Object { public: using Object::Object; };
} // namespace spec

class Key : public lang::Object { public: using Object::Object; };
class PrivateKey : public Key { public: PrivateKey(const lang::Object &init) : Key(init.object()) { } };
class PublicKey : public Key { public: PublicKey(const lang::Object &init) : Key(init.object()) { } };
class KeyPair : public lang::Object { public: using Object::Object; };

class KeyStore : public lang::Object {
public:
    using Object::Object;
    class Entry : public lang::Object { public: using Object::Object; };
    class PrivateKeyEntry : public Entry {
    public:
        using Entry::Entry;
        lang::Object getCertificate() const;
        lang::Object getPrivateKey() const;
    };
    bool containsAlias(const QString &alias) const;
    bool deleteEntry(const QString &alias) const;
    static KeyStore getInstance(const QString &type);
    lang::Object getEntry(const QString &alias, const lang::Object &param = lang::Object()) const;
    bool load(const lang::Object &param = lang::Object()) const;
};
} // namespace security
} // namespace java

namespace javax {
namespace crypto {
class SecretKey : public java::lang::Object { public: using Object::Object; };
class Cipher : public java::lang::Object {
public:
    using Object::Object;
    static const int DECRYPT_MODE;
    static const int ENCRYPT_MODE;
    static Cipher getInstance(const QString &transformation);
    bool init(int opMode, const java::lang::Object &key) const;
    bool init(int opMode, const java::lang::Object &key, const java::lang::Object &params) const;
    QByteArray doFinal(const QByteArray &input) const;
    QByteArray getIV() const;
};
namespace spec {
class IvParameterSpec : public java::lang::Object
{
public:
    using Object::Object;
    explicit IvParameterSpec(const QByteArray &iv);
};
} // namespace spec
} // namespace crypto

namespace security {
namespace cert {
class Certificate : public java::lang::Object
{
public:
    using Object::Object;
    java::lang::Object getPublicKey() const;
};
} // namespace cert

namespace auth {
namespace x500 {
class X500Principal : public java::lang::Object
{
public:
    using Object::Object;
    explicit X500Principal(const QString &name);
};
} // namespace x500
} // namespace auth
} // namespace security
} // namespace javax

namespace android {
namespace os {
class Build : public java::lang::Object
{
public:
    using Object::Object;
    static int SDK_INT();
};
} // namespace os
namespace content {
class Context : public java::lang::Object { public: using Object::Object; };
} // namespace content
namespace security {
class KeyPairGeneratorSpec : public java::lang::Object {
public:
    using Object::Object;
    class Builder : public java::lang::Object {
    public:
        using Object::Object;
        explicit Builder(const android::content::Context &context);
        Builder setAlias(const QString &alias) const;
        Builder setSubject(const javax::security::auth::x500::X500Principal &subject) const;
        Builder setSerialNumber(const java::lang::Object &serial) const;
        Builder setStartDate(const java::lang::Object &date) const;
        Builder setEndDate(const java::lang::Object &date) const;
        java::lang::Object build() const;
    };
};
namespace keystore {
class KeyGenParameterSpec : public java::lang::Object {
public:
    using Object::Object;
    class Builder : public java::lang::Object {
    public:
        using Object::Object;
        Builder(const QString &alias, int purposes);
        Builder setBlockModes(const QStringList &modes) const;
        Builder setEncryptionPaddings(const QStringList &paddings) const;
        Builder setUserAuthenticationRequired(bool required) const;
        Builder setInvalidatedByBiometricEnrollment(bool invalidate) const;
        java::lang::Object build() const;
    };
};
class KeyProperties : public java::lang::Object {
public:
    using Object::Object;
    static const int PURPOSE_ENCRYPT;
    static const int PURPOSE_DECRYPT;
    static const QString BLOCK_MODE_CBC;
    static const QString BLOCK_MODE_ECB;
    static const QString ENCRYPTION_PADDING_PKCS7;
    static const QString ENCRYPTION_PADDING_RSA_PKCS1;
};
} // namespace keystore

class KeyGenerator : public java::lang::Object
{
public:
    using Object::Object;
    static KeyGenerator getInstance(const QString &algorithm, const QString &provider);
    bool init(const java::lang::Object &spec) const;
    java::lang::Object generateKey() const;
};

class KeyPairGenerator : public java::lang::Object
{
public:
    using Object::Object;
    static KeyPairGenerator getInstance(const QString &algorithm, const QString &provider);
    java::lang::Object generateKeyPair() const;
    bool initialize(const java::lang::Object &spec) const;
};

} // namespace security

namespace hardware {
namespace biometrics {
class BiometricPrompt : public java::lang::Object
{
public:
    using Object::Object;
    class CryptoObject : public java::lang::Object
    {
    public:
        using Object::Object;
        explicit CryptoObject(const javax::crypto::Cipher &cipher);
    };
    class AuthenticationCallback : public java::lang::Object
    {
    public:
        using Object::Object;
    };
    class Builder : public java::lang::Object
    {
    public:
        using Object::Object;
        explicit Builder(const android::content::Context &context);
        Builder setTitle(const QString &title) const;
        Builder setNegativeButton(const QString &text, const java::lang::Object &executor, jobject listener) const;
        java::lang::Object build() const;
    };
    void authenticate(const CryptoObject &crypto, jobject cancellationSignal, const java::lang::Object &executor, const AuthenticationCallback &callback) const;
};
} // namespace biometrics
} // namespace hardware
} // namespace android

} // namespace QKeychain

#endif // QTKEYCHAIN_ANDROIDKEYSTORE_P_H
