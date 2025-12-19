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

namespace {

EM_JS(void, read_password, (JobPrivate* job, const char* key), {
    Asyncify.handleAsync(async () => {
        try {
            const cred = await navigator.credentials.get({
                password: true,
                id: UTF8ToString(key)
            });
            if (cred) {
                const password = cred.password;
                const buffer = Module._malloc(password.length);
                Module.stringToUTF8(password, buffer, password.length + 1);
                _read_password_success(job, buffer, password.length);
                Module._free(buffer);
            } else {
                _read_password_error(job, 1, "Password entry not found");
            }
        } catch (e) {
            _read_password_error(job, 6, e.toString());
        }
    });
});

EM_JS(void, write_password, (JobPrivate* job, const char* key, const char* data), {
    Asyncify.handleAsync(async () => {
        try {
            const credential = {
                id: UTF8ToString(key),
                password: UTF8ToString(data),
                name: UTF8ToString(key)
            };
            await navigator.credentials.store(new PasswordCredential(credential));
            _write_password_success(job);
        } catch (e) {
            _write_password_error(job, 6, e.toString());
        }
    });
});

}

extern "C" {

void EMSCRIPTEN_KEEPALIVE read_password_success(JobPrivate* job, const char* data, int length) {
    job->data = QByteArray(data, length);
    job->q->emitFinished();
}

void EMSCRIPTEN_KEEPALIVE read_password_error(JobPrivate* job, Error error, const char* errorString) {
    job->q->emitFinishedWithError(error, QString::fromUtf8(errorString));
}

void EMSCRIPTEN_KEEPALIVE write_password_success(JobPrivate* job) {
    job->q->emitFinished();
}

void EMSCRIPTEN_KEEPALIVE write_password_error(JobPrivate* job, Error error, const char* errorString) {
    job->q->emitFinishedWithError(error, QString::fromUtf8(errorString));
}

}

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
    return true;
}
