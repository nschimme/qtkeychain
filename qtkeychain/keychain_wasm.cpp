/******************************************************************************
 *   Copyright (C) 2024 Jules Software Engineer <jules@example.com>           *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"
#include <emscripten.h>

using namespace QKeychain;

// These functions will be called from JavaScript to complete the async operations.
extern "C" {

EMSCRIPTEN_KEEPALIVE
void qtkeychain_read_password_success(JobPrivate* job, const char* data, int length) {
    if (!job) return;
    job->data = QByteArray(data, length);
    job->q->emitFinished();
}

EMSCRIPTEN_KEEPALIVE
void qtkeychain_read_password_error(JobPrivate* job, int error, const char* errorString) {
    if (!job) return;
    job->q->emitFinishedWithError(static_cast<Error>(error), QString::fromUtf8(errorString));
}

EMSCRIPTEN_KEEPALIVE
void qtkeychain_write_password_success(JobPrivate* job) {
    if (!job) return;
    job->q->emitFinished();
}

EMSCRIPTEN_KEEPALIVE
void qtkeychain_write_password_error(JobPrivate* job, int error, const char* errorString) {
    if (!job) return;
    job->q->emitFinishedWithError(static_cast<Error>(error), QString::fromUtf8(errorString));
}

}

namespace {

// These EM_JS functions define the JavaScript side of the bridge.
// They call the C++ functions above upon promise resolution.
EM_JS(void, read_password, (JobPrivate* job, const char* key), {
    const keyStr = UTF8ToString(key);
    navigator.credentials.get({
        password: true,
        id: keyStr
    }).then(cred => {
        if (cred) {
            const password = cred.password;
            const buffer = Module._malloc(password.length + 1);
            Module.stringToUTF8(password, buffer, password.length + 1);
            _qtkeychain_read_password_success(job, buffer, password.length);
            Module._free(buffer);
        } else {
            // EntryNotFound is 1
            _qtkeychain_read_password_error(job, 1, "Password entry not found");
        }
    }).catch(e => {
        // OtherError is 6
        const errorStr = e.toString();
        const buffer = Module._malloc(errorStr.length + 1);
        Module.stringToUTF8(errorStr, buffer, errorStr.length + 1);
        _qtkeychain_read_password_error(job, 6, buffer);
        Module._free(buffer);
    });
});

EM_JS(void, write_password, (JobPrivate* job, const char* key, const char* data), {
    const credential = {
        id: UTF8ToString(key),
        password: UTF8ToString(data),
        name: UTF8ToString(key) // Or some other user-friendly name
    };
    navigator.credentials.store(new PasswordCredential(credential))
    .then(() => {
        _qtkeychain_write_password_success(job);
    }).catch(e => {
        // OtherError is 6
        const errorStr = e.toString();
        const buffer = Module._malloc(errorStr.length + 1);
        Module.stringToUTF8(errorStr, buffer, errorStr.length + 1);
        _qtkeychain_write_password_error(job, 6, buffer);
        Module._free(buffer);
    });
});

}

// scheduledStart implementations just kick off the JavaScript operations.
void ReadPasswordJobPrivate::scheduledStart()
{
    read_password(this, key.toUtf8().constData());
}

void WritePasswordJobPrivate::scheduledStart()
{
    write_password(this, key.toUtf8().constData(), data.constData());
}

void DeletePasswordJobPrivate::scheduledStart()
{
    q->emitFinishedWithError(NotImplemented, "Delete is not supported by the browser's Credential Management API");
}

bool QKeychain::isAvailable()
{
    // A better implementation could check `navigator.credentials` availability here.
    return true;
}
