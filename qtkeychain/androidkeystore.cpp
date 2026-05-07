#include "androidkeystore_p.h"

#if QT_VERSION < QT_VERSION_CHECK(5, 7, 0)
#  include "private/qjni_p.h"
#endif

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#  include <QAndroidJniEnvironment>
#endif

using namespace QKeychain;

using namespace android::content;
using namespace android::security;

using namespace java::io;
using namespace java::lang;
using namespace java::math;
using namespace java::util;
using namespace java::security;

using namespace javax::crypto;
using namespace javax::security::auth::x500;

const BigInteger BigInteger::ONE =
        BigInteger::getStaticObjectField("java/math/BigInteger", "ONE", "Ljava/math/BigInteger;");

const int Calendar::YEAR = Calendar::getStaticField<jint>("java/util/Calendar", "YEAR");

const int Cipher::DECRYPT_MODE =
        Cipher::getStaticField<jint>("javax/crypto/Cipher", "DECRYPT_MODE");
const int Cipher::ENCRYPT_MODE =
        Cipher::getStaticField<jint>("javax/crypto/Cipher", "ENCRYPT_MODE");

const int android::security::keystore::KeyProperties::PURPOSE_ENCRYPT =
        android::security::keystore::KeyProperties::getStaticField<jint>(
                "android/security/keystore/KeyProperties", "PURPOSE_ENCRYPT");
const int android::security::keystore::KeyProperties::PURPOSE_DECRYPT =
        android::security::keystore::KeyProperties::getStaticField<jint>(
                "android/security/keystore/KeyProperties", "PURPOSE_DECRYPT");
const QString android::security::keystore::KeyProperties::BLOCK_MODE_CBC =
        android::security::keystore::KeyProperties::getStaticObjectField(
                "android/security/keystore/KeyProperties", "BLOCK_MODE_CBC", "Ljava/lang/String;")
                .toString();
const QString android::security::keystore::KeyProperties::BLOCK_MODE_ECB =
        android::security::keystore::KeyProperties::getStaticObjectField(
                "android/security/keystore/KeyProperties", "BLOCK_MODE_ECB", "Ljava/lang/String;")
                .toString();
const QString android::security::keystore::KeyProperties::ENCRYPTION_PADDING_PKCS7 =
        android::security::keystore::KeyProperties::getStaticObjectField(
                "android/security/keystore/KeyProperties", "ENCRYPTION_PADDING_PKCS7",
                "Ljava/lang/String;")
                .toString();
const QString android::security::keystore::KeyProperties::ENCRYPTION_PADDING_RSA_PKCS1 =
        android::security::keystore::KeyProperties::getStaticObjectField(
                "android/security/keystore/KeyProperties", "ENCRYPTION_PADDING_RSA_PKCS1",
                "Ljava/lang/String;")
                .toString();

namespace {

#if QT_VERSION < QT_VERSION_CHECK(5, 7, 0)

struct JNIObject
{
    JNIObject(QSharedPointer<QJNIObjectPrivate> d) : d(d) { }

    static JNIObject fromLocalRef(jobject o)
    {
        return JNIObject(
                QSharedPointer<QJNIObjectPrivate>::create(QJNIObjectPrivate::fromLocalRef(o)));
    }

    jobject object() const { return d->object(); }
    QSharedPointer<QJNIObjectPrivate> d;
};

#else

using JNIObject = QAndroidJniObject;

#endif

QByteArray fromArray(const jbyteArray array)
{
    QAndroidJniEnvironment env;
    jbyte *const bytes = env->GetByteArrayElements(array, nullptr);
    const QByteArray result(reinterpret_cast<const char *>(bytes), env->GetArrayLength(array));
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

JNIObject toArray(const QByteArray &bytes)
{
    QAndroidJniEnvironment env;
    const int length = bytes.length();
    JNIObject array = JNIObject::fromLocalRef(env->NewByteArray(length));
    env->SetByteArrayRegion(static_cast<jbyteArray>(array.object()), 0, length,
                            reinterpret_cast<const jbyte *>(bytes.constData()));
    return array;
}

} // namespace

bool Object::handleExceptions()
{
    QAndroidJniEnvironment env;

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    return true;
}

KeyPairGenerator KeyPairGenerator::getInstance(const QString &algorithm, const QString &provider)
{
    return handleExceptions(callStaticObjectMethod(
            "java/security/KeyPairGenerator", "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
            fromString(algorithm).object(), fromString(provider).object()));
}

KeyGenerator KeyGenerator::getInstance(const QString &algorithm, const QString &provider)
{
    return handleExceptions(callStaticObjectMethod(
            "java/security/KeyGenerator", "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyGenerator;",
            fromString(algorithm).object(), fromString(provider).object()));
}

bool KeyGenerator::init(const java::lang::Object &spec) const
{
    callMethod<void>("init", "(Ljava/security/spec/AlgorithmParameterSpec;)V", spec.object());
    return handleExceptions();
}

SecretKey KeyGenerator::generateKey() const
{
    return handleExceptions(callObjectMethod("generateKey", "()Ljavax/crypto/SecretKey;"));
}

KeyPair KeyPairGenerator::generateKeyPair() const
{
    return handleExceptions(callObjectMethod("generateKeyPair", "()Ljava/security/KeyPair;"));
}

bool KeyPairGenerator::initialize(const java::lang::Object &spec) const
{
    callMethod<void>("initialize", "(Ljava/security/spec/AlgorithmParameterSpec;)V", spec.object());
    return handleExceptions();
}

bool KeyStore::containsAlias(const QString &alias) const
{
    return handleExceptions(callMethod<jboolean>("containsAlias", "(Ljava/lang/String;)Z",
                                                 fromString(alias).object()));
}

bool KeyStore::deleteEntry(const QString &alias) const
{
    callMethod<void>("deleteEntry", "(Ljava/lang/String;)V", fromString(alias).object());
    return handleExceptions();
}

KeyStore KeyStore::getInstance(const QString &type)
{
    return handleExceptions(callStaticObjectMethod("java/security/KeyStore", "getInstance",
                                                   "(Ljava/lang/String;)Ljava/security/KeyStore;",
                                                   fromString(type).object()));
}

KeyStore::Entry KeyStore::getEntry(const QString &alias,
                                   const java::lang::Object &param) const
{
    return handleExceptions(
            callObjectMethod("getEntry",
                             "(Ljava/lang/String;Ljava/security/"
                             "KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                             fromString(alias).object(), param.object()));
}

bool KeyStore::load(const java::lang::Object &param) const
{
    callMethod<void>("load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", param.object());
    return handleExceptions();
}

Calendar Calendar::getInstance()
{
    return handleExceptions(
            callStaticObjectMethod("java/util/Calendar", "getInstance", "()Ljava/util/Calendar;"));
}

bool Calendar::add(int field, int amount) const
{
    callMethod<void>("add", "(II)V", field, amount);
    return handleExceptions();
}

Date Calendar::getTime() const
{
    return handleExceptions(callObjectMethod("getTime", "()Ljava/util/Date;"));
}

android::security::KeyPairGeneratorSpec::Builder::Builder(const Context &context)
    : Object(QAndroidJniObject("android/security/KeyPairGeneratorSpec$Builder",
                               "(Landroid/content/Context;)V", context.object()))
{
    handleExceptions();
}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setAlias(const QString &alias) const
{
    return handleExceptions(callObjectMethod(
            "setAlias", "(Ljava/lang/String;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            fromString(alias).object()));
}

android::security::KeyPairGeneratorSpec::Builder
android::security::KeyPairGeneratorSpec::Builder::setSubject(const javax::security::auth::x500::X500Principal &subject) const
{
    return handleExceptions(callObjectMethod("setSubject",
                                             "(Ljavax/security/auth/x500/X500Principal;)Landroid/"
                                             "security/KeyPairGeneratorSpec$Builder;",
                                             subject.object()));
}

android::security::KeyPairGeneratorSpec::Builder
android::security::KeyPairGeneratorSpec::Builder::setSerialNumber(const BigInteger &serial) const
{
    return handleExceptions(callObjectMethod(
            "setSerialNumber",
            "(Ljava/math/BigInteger;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            serial.object()));
}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setStartDate(const Date &date) const
{
    return handleExceptions(callObjectMethod(
            "setStartDate", "(Ljava/util/Date;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            date.object()));
}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setEndDate(const Date &date) const
{
    return handleExceptions(callObjectMethod(
            "setEndDate", "(Ljava/util/Date;)Landroid/security/KeyPairGeneratorSpec$Builder;",
            date.object()));
}

android::security::KeyPairGeneratorSpec android::security::KeyPairGeneratorSpec::Builder::build() const
{
    return handleExceptions(callObjectMethod("build", "()Landroid/security/KeyPairGeneratorSpec;"));
}

android::security::keystore::KeyGenParameterSpec::Builder::Builder(const QString &alias,
                                                                   int purposes)
    : Object(QAndroidJniObject("android/security/keystore/KeyGenParameterSpec$Builder",
                               "(Ljava/lang/String;I)V", fromString(alias).object(), purposes))
{
    handleExceptions();
}

android::security::keystore::KeyGenParameterSpec::Builder
android::security::keystore::KeyGenParameterSpec::Builder::setBlockModes(
        const QStringList &modes) const
{
    QAndroidJniEnvironment env;
    jobjectArray array = env->NewObjectArray(modes.size(), env->FindClass("java/lang/String"),
                                             fromString(QString()).object());
    for (int i = 0; i < modes.size(); ++i) {
        env->SetObjectArrayElement(array, i, fromString(modes[i]).object());
    }
    return handleExceptions(callObjectMethod(
            "setBlockModes",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;", array));
}

android::security::keystore::KeyGenParameterSpec::Builder
android::security::keystore::KeyGenParameterSpec::Builder::setEncryptionPaddings(
        const QStringList &paddings) const
{
    QAndroidJniEnvironment env;
    jobjectArray array = env->NewObjectArray(paddings.size(), env->FindClass("java/lang/String"),
                                             fromString(QString()).object());
    for (int i = 0; i < paddings.size(); ++i) {
        env->SetObjectArrayElement(array, i, fromString(paddings[i]).object());
    }
    return handleExceptions(callObjectMethod(
            "setEncryptionPaddings",
            "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;", array));
}

android::security::keystore::KeyGenParameterSpec::Builder
android::security::keystore::KeyGenParameterSpec::Builder::setUserAuthenticationRequired(
        bool required) const
{
    return handleExceptions(callObjectMethod(
            "setUserAuthenticationRequired",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;", (jboolean)required));
}

android::security::keystore::KeyGenParameterSpec::Builder
android::security::keystore::KeyGenParameterSpec::Builder::setInvalidatedByBiometricEnrollment(
        bool invalidate) const
{
    return handleExceptions(callObjectMethod(
            "setInvalidatedByBiometricEnrollment",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;", (jboolean)invalidate));
}

android::security::keystore::KeyGenParameterSpec
android::security::keystore::KeyGenParameterSpec::Builder::build() const
{
    return handleExceptions(
            callObjectMethod("build", "()Landroid/security/keystore/KeyGenParameterSpec;"));
}

X500Principal::X500Principal(const QString &name)
    : Object(QAndroidJniObject("javax/security/auth/x500/X500Principal", "(Ljava/lang/String;)V",
                               fromString(name).object()))
{
    handleExceptions();
}

java::lang::Object KeyStore::PrivateKeyEntry::getCertificate() const
{
    return handleExceptions(
            callObjectMethod("getCertificate", "()Ljava/security/cert/Certificate;"));
}

PrivateKey KeyStore::PrivateKeyEntry::getPrivateKey() const
{
    return handleExceptions(callObjectMethod("getPrivateKey", "()Ljava/security/PrivateKey;"));
}

PublicKey javax::security::cert::Certificate::getPublicKey() const
{
    return handleExceptions(callObjectMethod("getPublicKey", "()Ljava/security/PublicKey;"));
}

ByteArrayInputStream::ByteArrayInputStream(const QByteArray &bytes)
    : InputStream(
              QAndroidJniObject("java/io/ByteArrayInputStream", "([B)V", toArray(bytes).object()))
{
}

ByteArrayOutputStream::ByteArrayOutputStream()
    : OutputStream(QAndroidJniObject("java/io/ByteArrayOutputStream"))
{
    handleExceptions();
}

QByteArray ByteArrayOutputStream::toByteArray() const
{
    const QAndroidJniObject wrapper = callObjectMethod<jbyteArray>("toByteArray");

    if (!handleExceptions())
        return QByteArray();

    return fromArray(static_cast<jbyteArray>(wrapper.object()));
}

int InputStream::read() const
{
    return handleExceptions(callMethod<int>("read"), -1);
}

int android::os::Build::SDK_INT()
{
    return getStaticField<jint>("android/os/Build$VERSION", "SDK_INT");
}

bool OutputStream::write(const QByteArray &bytes) const
{
    callMethod<void>("write", "([B)V", toArray(bytes).object());
    return handleExceptions();
}

bool OutputStream::close() const
{
    callMethod<void>("close");
    return handleExceptions();
}

bool OutputStream::flush() const
{
    callMethod<void>("flush");
    return handleExceptions();
}

Cipher Cipher::getInstance(const QString &transformation)
{
    return handleExceptions(callStaticObjectMethod("javax/crypto/Cipher", "getInstance",
                                                   "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                                                   fromString(transformation).object()));
}

bool Cipher::init(int opMode, const Key &key) const
{
    callMethod<void>("init", "(ILjava/security/Key;)V", opMode, key.object());
    return handleExceptions();
}

bool Cipher::init(int opMode, const Key &key, const java::lang::Object &params) const
{
    callMethod<void>("init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
                     opMode, key.object(), params.object());
    return handleExceptions();
}

QByteArray Cipher::doFinal(const QByteArray &input) const
{
    const QAndroidJniObject result = callObjectMethod("doFinal", "([B)[B", toArray(input).object());
    if (!handleExceptions())
        return QByteArray();
    return fromArray(static_cast<jbyteArray>(result.object()));
}

QByteArray Cipher::getIV() const
{
    const QAndroidJniObject result = callObjectMethod("getIV", "()[B");
    if (!handleExceptions() || !result.isValid())
        return QByteArray();
    return fromArray(static_cast<jbyteArray>(result.object()));
}

javax::crypto::spec::IvParameterSpec::IvParameterSpec(const QByteArray &iv)
    : java::lang::Object(
              QAndroidJniObject("javax/crypto/spec/IvParameterSpec", "([B)V", toArray(iv).object()))
{
}

CipherOutputStream::CipherOutputStream(const OutputStream &stream, const Cipher &cipher)
    : FilterOutputStream(QAndroidJniObject("javax/crypto/CipherOutputStream",
                                           "(Ljava/io/OutputStream;Ljavax/crypto/Cipher;)V",
                                           stream.object(), cipher.object()))
{
    handleExceptions();
}

CipherInputStream::CipherInputStream(const InputStream &stream, const Cipher &cipher)
    : FilterInputStream(QAndroidJniObject("javax/crypto/CipherInputStream",
                                          "(Ljava/io/InputStream;Ljavax/crypto/Cipher;)V",
                                          stream.object(), cipher.object()))
{
    handleExceptions();
}

android::hardware::biometrics::BiometricPrompt::CryptoObject::CryptoObject(const javax::crypto::Cipher &cipher)
    : Object(QAndroidJniObject("android/hardware/biometrics/BiometricPrompt$CryptoObject",
                               "(Ljavax/crypto/Cipher;)V", cipher.object()))
{
    handleExceptions();
}

android::hardware::biometrics::BiometricPrompt::Builder::Builder(const android::content::Context &context)
    : Object(QAndroidJniObject("android/hardware/biometrics/BiometricPrompt$Builder",
                               "(Landroid/content/Context;)V", context.object()))
{
    handleExceptions();
}

android::hardware::biometrics::BiometricPrompt::Builder
android::hardware::biometrics::BiometricPrompt::Builder::setTitle(const QString &title) const
{
    return handleExceptions(callObjectMethod(
            "setTitle", "(Ljava/lang/CharSequence;)Landroid/hardware/biometrics/BiometricPrompt$Builder;",
            fromString(title).object()));
}

android::hardware::biometrics::BiometricPrompt::Builder
android::hardware::biometrics::BiometricPrompt::Builder::setNegativeButton(
        const QString &text, const java::lang::Object &executor, jobject listener) const
{
    return handleExceptions(callObjectMethod(
            "setNegativeButton",
            "(Ljava/lang/CharSequence;Ljava/util/concurrent/Executor;Landroid/content/DialogInterface$OnClickListener;)Landroid/hardware/biometrics/BiometricPrompt$Builder;",
            fromString(text).object(), executor.object(), listener));
}

android::hardware::biometrics::BiometricPrompt
android::hardware::biometrics::BiometricPrompt::Builder::build() const
{
    return handleExceptions(callObjectMethod("build", "()Landroid/hardware/biometrics/BiometricPrompt;"));
}

void android::hardware::biometrics::BiometricPrompt::authenticate(
        const CryptoObject &crypto, jobject cancellationSignal, const java::lang::Object &executor,
        const AuthenticationCallback &callback) const
{
    callMethod<void>("authenticate",
                     "(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;Landroid/os/CancellationSignal;Ljava/util/concurrent/Executor;Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V",
                     crypto.object(), cancellationSignal, executor.object(), callback.object());
    handleExceptions();
}
