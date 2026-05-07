#include "androidkeystore_p.h"

using namespace QKeychain;

using namespace android::content;
using namespace android::security;

using namespace java::lang;
using namespace java::util;

namespace {

QByteArray fromArray(const jbyteArray array)
{
    QJniEnvironment env;
    jbyte *const bytes = env->GetByteArrayElements(array, nullptr);
    const QByteArray result(reinterpret_cast<const char *>(bytes), env->GetArrayLength(array));
    env->ReleaseByteArrayElements(array, bytes, JNI_ABORT);
    return result;
}

jbyteArray toArray(const QByteArray &bytes)
{
    QJniEnvironment env;
    const int length = bytes.length();
    jbyteArray array = env->NewByteArray(length);
    env->SetByteArrayRegion(array, 0, length, reinterpret_cast<const jbyte *>(bytes.constData()));
    return array;
}

} // namespace

bool java::lang::Object::handleExceptions()
{
    QJniEnvironment env;
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }
    return true;
}

const int java::util::Calendar::YEAR = 1;

java::util::Calendar java::util::Calendar::getInstance()
{
    return handleExceptions(QJniObject::callStaticObjectMethod("java/util/Calendar", "getInstance", "()Ljava/util/Calendar;"));
}

bool java::util::Calendar::add(int field, int amount) const
{
    callMethod<void>("add", "(II)V", field, amount);
    return handleExceptions();
}

java::lang::Object java::util::Calendar::getTime() const
{
    return handleExceptions(callObjectMethod("getTime", "()Ljava/util/Date;"));
}

const int javax::crypto::Cipher::DECRYPT_MODE = 2;
const int javax::crypto::Cipher::ENCRYPT_MODE = 1;

javax::crypto::Cipher javax::crypto::Cipher::getInstance(const QString &transformation)
{
    return handleExceptions(QJniObject::callStaticObjectMethod("javax/crypto/Cipher", "getInstance",
                                                   "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                                                   QJniObject::fromString(transformation).object()));
}

bool javax::crypto::Cipher::init(int opMode, const java::lang::Object &key) const
{
    callMethod<void>("init", "(ILjava/security/Key;)V", opMode, key.object());
    return handleExceptions();
}

bool javax::crypto::Cipher::init(int opMode, const java::lang::Object &key, const java::lang::Object &params) const
{
    callMethod<void>("init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
                     opMode, key.object(), params.object());
    return handleExceptions();
}

QByteArray javax::crypto::Cipher::doFinal(const QByteArray &input) const
{
    const QJniObject result = callObjectMethod("doFinal", "([B)[B", toArray(input));
    if (!handleExceptions()) return QByteArray();
    return fromArray(static_cast<jbyteArray>(result.object()));
}

QByteArray javax::crypto::Cipher::getIV() const
{
    const QJniObject result = callObjectMethod("getIV", "()[B");
    if (!handleExceptions() || !result.isValid()) return QByteArray();
    return fromArray(static_cast<jbyteArray>(result.object()));
}

javax::crypto::spec::IvParameterSpec::IvParameterSpec(const QByteArray &iv)
    : java::lang::Object(QJniObject("javax/crypto/spec/IvParameterSpec", "([B)V", toArray(iv)))
{
}

const int android::security::keystore::KeyProperties::PURPOSE_ENCRYPT = 1;
const int android::security::keystore::KeyProperties::PURPOSE_DECRYPT = 2;
const QString android::security::keystore::KeyProperties::BLOCK_MODE_CBC = QStringLiteral("CBC");
const QString android::security::keystore::KeyProperties::BLOCK_MODE_ECB = QStringLiteral("ECB");
const QString android::security::keystore::KeyProperties::ENCRYPTION_PADDING_PKCS7 = QStringLiteral("PKCS7Padding");
const QString android::security::keystore::KeyProperties::ENCRYPTION_PADDING_RSA_PKCS1 = QStringLiteral("PKCS1Padding");

java::security::KeyGenerator java::security::KeyGenerator::getInstance(const QString &algorithm, const QString &provider)
{
    return handleExceptions(QJniObject::callStaticObjectMethod(
            "javax/crypto/KeyGenerator", "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            QJniObject::fromString(algorithm).object(), QJniObject::fromString(provider).object()));
}

bool java::security::KeyGenerator::init(const java::lang::Object &spec) const
{
    callMethod<void>("init", "(Ljava/security/spec/AlgorithmParameterSpec;)V", spec.object());
    return handleExceptions();
}

java::lang::Object java::security::KeyGenerator::generateKey() const
{
    return handleExceptions(callObjectMethod("generateKey", "()Ljavax/crypto/SecretKey;"));
}

java::security::KeyPairGenerator java::security::KeyPairGenerator::getInstance(const QString &algorithm, const QString &provider)
{
    return handleExceptions(QJniObject::callStaticObjectMethod(
            "java/security/KeyPairGenerator", "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
            QJniObject::fromString(algorithm).object(), QJniObject::fromString(provider).object()));
}

java::lang::Object java::security::KeyPairGenerator::generateKeyPair() const
{
    return handleExceptions(callObjectMethod("generateKeyPair", "()Ljava/security/KeyPair;"));
}

bool java::security::KeyPairGenerator::initialize(const java::lang::Object &spec) const
{
    callMethod<void>("initialize", "(Ljava/security/spec/AlgorithmParameterSpec;)V", spec.object());
    return handleExceptions();
}

bool java::security::KeyStore::containsAlias(const QString &alias) const
{
    return handleExceptions(callMethod<jboolean>("containsAlias", "(Ljava/lang/String;)Z",
                                                 QJniObject::fromString(alias).object()));
}

bool java::security::KeyStore::deleteEntry(const QString &alias) const
{
    callMethod<void>("deleteEntry", "(Ljava/lang/String;)V", QJniObject::fromString(alias).object());
    return handleExceptions();
}

java::security::KeyStore java::security::KeyStore::getInstance(const QString &type)
{
    return handleExceptions(QJniObject::callStaticObjectMethod("java/security/KeyStore", "getInstance",
                                                   "(Ljava/lang/String;)Ljava/security/KeyStore;",
                                                   QJniObject::fromString(type).object()));
}

java::lang::Object java::security::KeyStore::getEntry(const QString &alias, const java::lang::Object &param) const
{
    return handleExceptions(callObjectMethod("getEntry",
                             "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;",
                             QJniObject::fromString(alias).object(), param.object()));
}

bool java::security::KeyStore::load(const java::lang::Object &param) const
{
    callMethod<void>("load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", param.object());
    return handleExceptions();
}

java::lang::Object java::security::KeyStore::PrivateKeyEntry::getCertificate() const
{
    return handleExceptions(callObjectMethod("getCertificate", "()Ljava/security/cert/Certificate;"));
}

java::lang::Object java::security::KeyStore::PrivateKeyEntry::getPrivateKey() const
{
    return handleExceptions(callObjectMethod("getPrivateKey", "()Ljava/security/PrivateKey;"));
}

java::lang::Object javax::security::cert::Certificate::getPublicKey() const
{
    return handleExceptions(callObjectMethod("getPublicKey", "()Ljava/security/PublicKey;"));
}

const java::math::BigInteger java::math::BigInteger::ONE = java::math::BigInteger(QJniObject::getStaticObjectField("java/math/BigInteger", "ONE", "Ljava/math/BigInteger;"));

int android::os::Build::SDK_INT()
{
    return QJniObject::getStaticField<jint>("android/os/Build$VERSION", "SDK_INT");
}

android::security::KeyPairGeneratorSpec::Builder::Builder(const android::content::Context &context)
    : java::lang::Object(QJniObject("android/security/KeyPairGeneratorSpec$Builder", "(Landroid/content/Context;)V", context.object())) {}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setAlias(const QString &alias) const
{
    return handleExceptions(callObjectMethod("setAlias", "(Ljava/lang/String;)android/security/KeyPairGeneratorSpec$Builder;", QJniObject::fromString(alias).object()));
}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setSubject(const javax::security::auth::x500::X500Principal &subject) const
{
    return handleExceptions(callObjectMethod("setSubject", "(Ljavax/security/auth/x500/X500Principal;)android/security/KeyPairGeneratorSpec$Builder;", subject.object()));
}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setSerialNumber(const java::lang::Object &serial) const
{
    return handleExceptions(callObjectMethod("setSerialNumber", "(Ljava/math/BigInteger;)android/security/KeyPairGeneratorSpec$Builder;", serial.object()));
}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setStartDate(const java::lang::Object &date) const
{
    return handleExceptions(callObjectMethod("setStartDate", "(Ljava/util/Date;)android/security/KeyPairGeneratorSpec$Builder;", date.object()));
}

android::security::KeyPairGeneratorSpec::Builder android::security::KeyPairGeneratorSpec::Builder::setEndDate(const java::lang::Object &date) const
{
    return handleExceptions(callObjectMethod("setEndDate", "(Ljava/util/Date;)android/security/KeyPairGeneratorSpec$Builder;", date.object()));
}

java::lang::Object android::security::KeyPairGeneratorSpec::Builder::build() const
{
    return handleExceptions(callObjectMethod("build", "()Landroid/security/KeyPairGeneratorSpec;"));
}

android::security::keystore::KeyGenParameterSpec::Builder::Builder(const QString &alias, int purposes)
    : java::lang::Object(QJniObject("android/security/keystore/KeyGenParameterSpec$Builder", "(Ljava/lang/String;I)V", QJniObject::fromString(alias).object(), purposes)) {}

android::security::keystore::KeyGenParameterSpec::Builder android::security::keystore::KeyGenParameterSpec::Builder::setBlockModes(const QStringList &modes) const
{
    QJniEnvironment env;
    jobjectArray array = env->NewObjectArray(modes.size(), env->FindClass("java/lang/String"), QJniObject::fromString(QString()).object());
    for (int i = 0; i < modes.size(); ++i) env->SetObjectArrayElement(array, i, QJniObject::fromString(modes[i]).object());
    return handleExceptions(callObjectMethod("setBlockModes", "([Ljava/lang/String;)android/security/keystore/KeyGenParameterSpec$Builder;", array));
}

android::security::keystore::KeyGenParameterSpec::Builder android::security::keystore::KeyGenParameterSpec::Builder::setEncryptionPaddings(const QStringList &paddings) const
{
    QJniEnvironment env;
    jobjectArray array = env->NewObjectArray(paddings.size(), env->FindClass("java/lang/String"), QJniObject::fromString(QString()).object());
    for (int i = 0; i < paddings.size(); ++i) env->SetObjectArrayElement(array, i, QJniObject::fromString(paddings[i]).object());
    return handleExceptions(callObjectMethod("setEncryptionPaddings", "([Ljava/lang/String;)android/security/keystore/KeyGenParameterSpec$Builder;", array));
}

android::security::keystore::KeyGenParameterSpec::Builder android::security::keystore::KeyGenParameterSpec::Builder::setUserAuthenticationRequired(bool required) const
{
    return handleExceptions(callObjectMethod("setUserAuthenticationRequired", "(Z)android/security/keystore/KeyGenParameterSpec$Builder;", (jboolean)required));
}

android::security::keystore::KeyGenParameterSpec::Builder android::security::keystore::KeyGenParameterSpec::Builder::setInvalidatedByBiometricEnrollment(bool invalidate) const
{
    return handleExceptions(callObjectMethod("setInvalidatedByBiometricEnrollment", "(Z)android/security/keystore/KeyGenParameterSpec$Builder;", (jboolean)invalidate));
}

java::lang::Object android::security::keystore::KeyGenParameterSpec::Builder::build() const
{
    return handleExceptions(callObjectMethod("build", "()Landroid/security/keystore/KeyGenParameterSpec;"));
}

javax::security::auth::x500::X500Principal::X500Principal(const QString &name)
    : java::lang::Object(QJniObject("javax/security/auth/x500/X500Principal", "(Ljava/lang/String;)V", QJniObject::fromString(name).object())) {}

android::hardware::biometrics::BiometricPrompt::CryptoObject::CryptoObject(const javax::crypto::Cipher &cipher)
    : java::lang::Object(QJniObject("android/hardware/biometrics/BiometricPrompt$CryptoObject", "(Ljavax/crypto/Cipher;)V", cipher.object())) {}

android::hardware::biometrics::BiometricPrompt::Builder::Builder(const android::content::Context &context)
    : java::lang::Object(QJniObject("android/hardware/biometrics/BiometricPrompt$Builder", "(Landroid/content/Context;)V", context.object())) {}

android::hardware::biometrics::BiometricPrompt::Builder android::hardware::biometrics::BiometricPrompt::Builder::setTitle(const QString &title) const
{
    return handleExceptions(callObjectMethod("setTitle", "(Ljava/lang/CharSequence;)android/hardware/biometrics/BiometricPrompt$Builder;", QJniObject::fromString(title).object()));
}

android::hardware::biometrics::BiometricPrompt::Builder android::hardware::biometrics::BiometricPrompt::Builder::setNegativeButton(const QString &text, const java::lang::Object &executor, jobject listener) const
{
    return handleExceptions(callObjectMethod("setNegativeButton", "(Ljava/lang/CharSequence;Ljava/util/concurrent/Executor;Landroid/content/DialogInterface$OnClickListener;)android/hardware/biometrics/BiometricPrompt$Builder;", QJniObject::fromString(text).object(), executor.object(), listener));
}

java::lang::Object android::hardware::biometrics::BiometricPrompt::Builder::build() const
{
    return handleExceptions(callObjectMethod("build", "()Landroid/hardware/biometrics/BiometricPrompt;"));
}

void android::hardware::biometrics::BiometricPrompt::authenticate(const CryptoObject &crypto, jobject cancellationSignal, const java::lang::Object &executor, const AuthenticationCallback &callback) const
{
    callMethod<void>("authenticate", "(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;Landroid/os/CancellationSignal;Ljava/util/concurrent/Executor;Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;)V", crypto.object(), cancellationSignal, executor.object(), callback.object());
    handleExceptions();
}
