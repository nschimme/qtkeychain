/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"
#include "plaintextstore_p.h"

#include <comdef.h>
#include <windows.h>
#include <wincred.h>
#include <wincrypt.h>
#include <winuser.h>

#include <cmath>
#include <memory>

using namespace QKeychain;

namespace {
const std::wstring PRODUCT_NAME = L"QtKeychain";
const std::wstring ENCRYPTED_DATA_KEY = L"QtKeychain-encrypted data";
const std::wstring ATTRIBUTE_KEY = L"QtKeychain Attrib";

constexpr quint64 MAX_ATTRIBUTE_SIZE = 256;
constexpr quint64 MAX_ATTRIBUTE_COUNT = 64;
constexpr qsizetype MAX_BLOB_SIZE =
        CRED_MAX_CREDENTIAL_BLOB_SIZE + MAX_ATTRIBUTE_SIZE * MAX_ATTRIBUTE_COUNT;

QString formatWinError(ulong errorCode)
{
    return QStringLiteral("WindowsError: %1: %2")
            .arg(QString::number(errorCode, 16),
                 QString::fromWCharArray(_com_error(errorCode).ErrorMessage()));
}

// decrpyted data, error
std::pair<QByteArray, QString> unprotectData(const QByteArray &encrypted)
{
    DATA_BLOB blob_in, blob_out;

    blob_in.pbData =
            const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(encrypted.data()));
    blob_in.cbData = encrypted.size();

    if (!CryptUnprotectData(&blob_in, nullptr, nullptr, nullptr, nullptr, 0, &blob_out)) {
        return { {}, formatWinError(GetLastError()) };
    }

    QByteArray decrypted(reinterpret_cast<char *>(blob_out.pbData), blob_out.cbData);
    SecureZeroMemory(blob_out.pbData, blob_out.cbData);
    LocalFree(blob_out.pbData);
    return { decrypted, {} };
}

// encrypted data, error
std::pair<QByteArray, QString> protectData(const QByteArray &data)
{
    DATA_BLOB blob_in, blob_out;
    blob_in.pbData =
            const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(data.data()));
    blob_in.cbData = data.size();
    if (!CryptProtectData(&blob_in, ENCRYPTED_DATA_KEY.data(), nullptr, nullptr, nullptr, 0,
                          &blob_out)) {

        return { {}, formatWinError(GetLastError()) };
    }

    QByteArray encrypted(reinterpret_cast<char *>(blob_out.pbData), blob_out.cbData);
    LocalFree(blob_out.pbData);
    return { encrypted, {} };
}

bool isWindowsHelloAvailable()
{
    // Heuristic: check if Windows 10 or newer
    OSVERSIONINFOEXW osi = { sizeof(osi), 10, 0, 0, 0, {0}, 0, 0, 0, 0, 0 };
    DWORDLONG mask = 0;
    VER_SET_CONDITION(mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(mask, VER_MINORVERSION, VER_GREATER_EQUAL);

    return VerifyVersionInfoW(&osi, VER_MAJORVERSION | VER_MINORVERSION, mask);
}

bool verifyUserPresence(const QString &service)
{
    if (!isWindowsHelloAvailable())
        return true;

    // Use dynamic loading to avoid build-time dependency on credui.h/credui.lib
    typedef struct _CREDUI_INFOW {
        DWORD cbSize;
        HWND hwndParent;
        LPCWSTR pszMessageText;
        LPCWSTR pszCaptionText;
        HBITMAP hbmBanner;
    } CREDUI_INFOW, *PCREDUI_INFOW;

    typedef DWORD (WINAPI *PFN_CredUIPromptForWindowsCredentialsW)(
        PCREDUI_INFOW pUiInfo, DWORD dwAuthError, ULONG *pAuthPackage,
        LPCVOID pvInAuthBuffer, ULONG ulInAuthBufferSize,
        LPVOID *ppvOutAuthBuffer, ULONG *pulOutAuthBufferSize,
        PBOOL pfSave, DWORD dwFlags);

    HMODULE hCredUI = LoadLibraryW(L"credui.dll");
    if (!hCredUI)
        return true;

    PFN_CredUIPromptForWindowsCredentialsW pPrompt =
        (PFN_CredUIPromptForWindowsCredentialsW)GetProcAddress(hCredUI, "CredUIPromptForWindowsCredentialsW");

    if (!pPrompt) {
        FreeLibrary(hCredUI);
        return true;
    }

    CREDUI_INFOW credui = {};
    credui.cbSize = sizeof(credui);
    credui.hwndParent = nullptr;

    const QString message = QObject::tr("Authenticate to access %1").arg(service);
    credui.pszMessageText = reinterpret_cast<const wchar_t *>(message.utf16());
    credui.pszCaptionText = L"QtKeychain";

    ULONG authPackage = 0;
    LPVOID authBuffer = nullptr;
    ULONG authBufferSize = 0;
    BOOL save = FALSE;

    // Flags: CREDUIWIN_GENERIC (0x1) | CREDUIWIN_ALLOW_UNKNOWN_SCHEME (0x2) | CREDUIWIN_ENUMERATE_CURRENT_USER (0x200)
    const DWORD status = pPrompt(
            &credui, 0, &authPackage, nullptr, 0, &authBuffer, &authBufferSize, &save,
            0x1 | 0x2 | 0x200);

    if (status == ERROR_SUCCESS) {
        if (authBuffer) {
            SecureZeroMemory(authBuffer, authBufferSize);
            CoTaskMemFree(authBuffer);
        }
        FreeLibrary(hCredUI);
        return true;
    }

    FreeLibrary(hCredUI);
    return false;
}

} // namespace

#if defined(USE_CREDENTIAL_STORE)

/***
 * The credentials store has a limit of CRED_MAX_CREDENTIAL_BLOB_SIZE (5* 512)
 * As this might not be enough in some scenarios, for bigger payloads we use CryptProtectData which
 * offers similar protection as CredWrite in combination with CredWrite. We distribute the protected
 * payload to the PCREDENTIALW->CredentialBlob as well as PCREDENTIALW->AttributeCount. This
 * increases the max payload size to CRED_MAX_CREDENTIAL_BLOB_SIZE + 64 * 256 = 18944. As the
 * protected data requires more space than the original payload, the effective max payload is
 * smaller than that. As we continue to use PCREDENTIALW as storage medium, the credentials are
 * still roaming.
 */
void ReadPasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (!verifyUserPresence(q->service())) {
            q->emitFinishedWithError(AccessDeniedByUser, tr("User canceled authentication"));
            return;
        }
    }

    PCREDENTIALW cred = {};

    if (!CredReadW(reinterpret_cast<const wchar_t *>(key.utf16()), CRED_TYPE_GENERIC, 0, &cred)) {
        Error err;
        QString msg;
        switch (GetLastError()) {
        case ERROR_NOT_FOUND:
            err = EntryNotFound;
            msg = tr("Password entry not found");
            break;
        default:
            err = OtherError;
            msg = tr("Could not decrypt data");
            break;
        }

        q->emitFinishedWithError(err, msg);
        return;
    }

    if (cred->AttributeCount == 0) {
        data = QByteArray(reinterpret_cast<char *>(cred->CredentialBlob), cred->CredentialBlobSize);
    } else {
        QByteArray encrypted;
        encrypted.reserve(CRED_MAX_CREDENTIAL_BLOB_SIZE
                          + cred->AttributeCount * MAX_ATTRIBUTE_SIZE);
        encrypted.append(reinterpret_cast<char *>(cred->CredentialBlob), cred->CredentialBlobSize);
        for (ulong i = 0; i < cred->AttributeCount; ++i) {
            encrypted.append(reinterpret_cast<char *>(cred->Attributes[i].Value),
                             cred->Attributes[i].ValueSize);
        }
        const auto result = unprotectData(encrypted);
        if (!result.second.isEmpty()) {
            q->emitFinishedWithError(OtherError,
                                     tr("Could not decrypt data: %1").arg(result.second));
            return;
        }
        data = result.first;
    }

    CredFree(cred);

    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (!verifyUserPresence(q->service())) {
            q->emitFinishedWithError(AccessDeniedByUser, tr("User canceled authentication"));
            return;
        }
    }

    CREDENTIALW cred = {};
    cred.Comment = const_cast<wchar_t *>(PRODUCT_NAME.data());
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<wchar_t *>(reinterpret_cast<const wchar_t *>(key.utf16()));
    cred.Persist = CRED_PERSIST_ENTERPRISE;

    QByteArray buffer;
    std::vector<CREDENTIAL_ATTRIBUTEW> attributes;

    if (data.size() < CRED_MAX_CREDENTIAL_BLOB_SIZE) {
        cred.CredentialBlob = reinterpret_cast<uchar *>(data.data());
        cred.CredentialBlobSize = data.size();
    } else {
        // data is too big for CredentialBlob
        // we encrpyt it instead with CryptProtectData which also encrpyt the data with the users
        // credentials The data is also protected with the roaming profile
        {
            auto result = protectData(data);
            if (!result.second.isEmpty()) {
                q->emitFinishedWithError(OtherError,
                                         tr("Encryption failed: %1").arg(result.second));
                return;
            }
            if (result.first.size() > MAX_BLOB_SIZE) {
                q->emitFinishedWithError(OtherError,
                                         tr("Credential size exceeds maximum size of %1: %2")
                                                 .arg(QString::number(MAX_BLOB_SIZE),
                                                      QString::number(result.first.size())));
                return;
            }
            // the data must be valid outside of the scope of result
            buffer = std::move(result.first);
        }

        quint64 pos = 0;
        auto read = [&buffer, &pos](const quint64 size, auto &dest, auto &sizeOut) {
            dest = reinterpret_cast<typename std::remove_reference<decltype(dest)>::type>(
                           buffer.data())
                    + pos;
            sizeOut = std::min<ulong>(size, buffer.size() - pos);
            pos += sizeOut;
        };
        read(CRED_MAX_CREDENTIAL_BLOB_SIZE, cred.CredentialBlob, cred.CredentialBlobSize);

        cred.AttributeCount =
                std::ceil((buffer.size() - pos) / static_cast<double>(MAX_ATTRIBUTE_SIZE));
        attributes.resize(cred.AttributeCount, {});
        cred.Attributes = attributes.data();
        for (ulong i = 0; i < cred.AttributeCount; ++i) {
            attributes[i].Keyword = const_cast<wchar_t *>(ATTRIBUTE_KEY.data());
            read(MAX_ATTRIBUTE_SIZE, attributes[i].Value, attributes[i].ValueSize);
        }
    }
    if (CredWriteW(&cred, 0)) {
        q->emitFinished();
        return;
    }

    const DWORD err = GetLastError();

    // Detect size-exceeded errors and provide nicer messages.
    // Unfortunately these error codes aren't documented.
    // Found empirically on Win10 1803 build 17134.523.
    if (err == RPC_S_INVALID_BOUND) {
        const QString::size_type maxTargetName = CRED_MAX_GENERIC_TARGET_NAME_LENGTH;
        if (key.size() > maxTargetName) {
            q->emitFinishedWithError(
                    OtherError, tr("Credential key exceeds maximum size of %1").arg(maxTargetName));
            return;
        }
    }

    q->emitFinishedWithError(OtherError,
                             tr("Writing credentials failed: %1").arg(formatWinError(err)));
}

void DeletePasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (!verifyUserPresence(q->service())) {
            q->emitFinishedWithError(AccessDeniedByUser, tr("User canceled authentication"));
            return;
        }
    }

    if (!CredDeleteW(reinterpret_cast<const wchar_t *>(key.utf16()), CRED_TYPE_GENERIC, 0)) {
        Error err;
        QString msg;
        switch (GetLastError()) {
        case ERROR_NOT_FOUND:
            err = EntryNotFound;
            msg = tr("Password entry not found");
            break;
        default:
            err = OtherError;
            msg = tr("Could not decrypt data");
            break;
        }

        q->emitFinishedWithError(err, msg);
    } else {
        q->emitFinished();
    }
}
#else
void ReadPasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (!verifyUserPresence(q->service())) {
            q->emitFinishedWithError(AccessDeniedByUser, tr("User canceled authentication"));
            return;
        }
    }

    PlainTextStore plainTextStore(q->service(), q->settings());
    QByteArray encrypted = plainTextStore.readData(key);
    if (plainTextStore.error() != NoError) {
        q->emitFinishedWithError(plainTextStore.error(), plainTextStore.errorString());
        return;
    }

    const auto result = unprotectData(encrypted);
    if (!result.second.isEmpty()) {
        q->emitFinishedWithError(OtherError, tr("Could not decrypt data: %1").arg(result.second));
        return;
    }
    data = result.first;
    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (!verifyUserPresence(q->service())) {
            q->emitFinishedWithError(AccessDeniedByUser, tr("User canceled authentication"));
            return;
        }
    }

    const auto result = protectData(data);
    if (!result.second.isEmpty()) {
        q->emitFinishedWithError(OtherError, tr("Encryption failed: %1").arg(result.second));
        return;
    }

    PlainTextStore plainTextStore(q->service(), q->settings());
    plainTextStore.write(key, result.first, Binary);
    if (plainTextStore.error() != NoError) {
        q->emitFinishedWithError(plainTextStore.error(), plainTextStore.errorString());
        return;
    }

    q->emitFinished();
}

void DeletePasswordJobPrivate::scheduledStart()
{
    if (securityLevel == Job::Biometric) {
        if (!verifyUserPresence(q->service())) {
            q->emitFinishedWithError(AccessDeniedByUser, tr("User canceled authentication"));
            return;
        }
    }

    PlainTextStore plainTextStore(q->service(), q->settings());
    plainTextStore.remove(key);
    if (plainTextStore.error() != NoError) {
        q->emitFinishedWithError(plainTextStore.error(), plainTextStore.errorString());
    } else {
        q->emitFinished();
    }
}
#endif

bool QKeychain::isAvailable()
{
    return true;
}
