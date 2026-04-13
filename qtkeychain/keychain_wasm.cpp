/******************************************************************************
 *   Copyright (C) 2025 Nils Schimmelmann <nschimme@gmail.com>                *
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
void qtkeychain_write_password_success(JobPrivate* job) {
    if (!job) return;
    job->q->emitFinished();
}

EMSCRIPTEN_KEEPALIVE
void qtkeychain_error(JobPrivate* job, int error, const char* errorString) {
    if (!job) return;
    job->q->emitFinishedWithError(static_cast<Error>(error), QString::fromUtf8(errorString));
}

}

namespace {

EM_JS(void, show_bridge_form, (JobPrivate* job, const char* service, const char* key, const char* data, bool isWrite, int entryNotFound, int accessDeniedByUser, int otherError), {
    const serviceStr = UTF8ToString(service);
    const keyStr = UTF8ToString(key);
    const dataStr = UTF8ToString(data);

    // CSS
    const styleId = 'qtkeychain-styles';
    if (!document.getElementById(styleId)) {
        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = `
            [id="qtkeychain-overlay"] {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0, 0, 0, 0.5); display: flex;
                justify-content: center; align-items: center; z-index: 2147483647;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            }
            [id="qtkeychain-modal"] {
                background: white; padding: 24px; border-radius: 12px;
                box-shadow: 0 8px 30px rgba(0,0,0,0.3); width: 320px; color: #333;
            }
            [id="qtkeychain-modal"] h2 { margin: 0 0 16px 0; font-size: 1.1em; font-weight: 600; }
            [id="qtkeychain-modal"] label { display: block; margin-bottom: 6px; font-size: 0.9em; font-weight: 500; }
            [id="qtkeychain-modal"] input {
                width: 100%; margin-bottom: 16px; padding: 10px;
                border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; font-size: 1em;
            }
            [id="qtkeychain-modal"] .actions { display: flex; flex-direction: row-reverse; gap: 8px; margin-top: 16px; }
            [id="qtkeychain-modal"] button {
                flex: 1; padding: 10px; border-radius: 6px; border: none; font-size: 1em; cursor: pointer; font-weight: 500;
            }
            [id="qtkeychain-modal"] .btn-primary { background: #007aff; color: white; }
            [id="qtkeychain-modal"] .btn-secondary { background: #e5e5ea; color: #333; }
            [id="qtkeychain-modal"] .btn-success { background: #28a745; color: white; }
        `;
        document.head.appendChild(style);
    }

    const overlay = document.createElement('div');
    overlay.id = 'qtkeychain-overlay';

    const modal = document.createElement('div');
    modal.id = 'qtkeychain-modal';
    overlay.appendChild(modal);

    const title = document.createElement('h2');
    title.textContent = serviceStr;
    modal.appendChild(title);

    const form = document.createElement('form');
    form.id = 'qtkeychain-form';
    if (isWrite) {
        // Create hidden iframe for legacy submission fallback
        const iframeId = 'qtkeychain-iframe';
        let iframe = document.getElementById(iframeId);
        if (!iframe) {
            iframe = document.createElement('iframe');
            iframe.id = iframeId;
            iframe.name = iframeId;
            iframe.style.display = 'none';
            document.body.appendChild(iframe);
        }
        form.target = iframeId;
        form.action = 'about:blank'; // Trigger browser save without reloading main page
    }
    modal.appendChild(form);

    const createField = (label, id, type, autocomplete, value) => {
        const lbl = document.createElement('label');
        lbl.textContent = label;
        lbl.htmlFor = id;
        form.appendChild(lbl);
        const input = document.createElement('input');
        input.id = id;
        input.type = type;
        input.name = (type === 'password' ? 'password' : 'username');
        input.autocomplete = autocomplete;
        input.value = value;
        form.appendChild(input);
        return input;
    };

    const userInput = createField('Username', 'qtkeychain-username', 'text', 'username', keyStr);
    const passInput = createField('Password', 'qtkeychain-password', 'password',
                                  isWrite ? 'new-password' : 'current-password', isWrite ? dataStr : '');

    if (!isWrite && navigator.credentials && navigator.credentials.get && typeof PasswordCredential !== 'undefined') {
        const pickBtn = document.createElement('button');
        pickBtn.type = 'button';
        pickBtn.className = 'btn-success';
        pickBtn.style.marginBottom = '16px';
        pickBtn.style.display = 'block';
        pickBtn.style.width = '100%';
        pickBtn.textContent = 'Use a saved password...';
        pickBtn.onclick = () => {
            console.log("QtKeychain: Requesting credentials from browser...");
            navigator.credentials.get({ password: true })
            .then(cred => {
                if (cred) {
                    console.log("QtKeychain: Credential received");
                    userInput.value = cred.id || "";
                    passInput.value = cred.password || "";
                    // Auto-submit after picking
                    form.dispatchEvent(new Event("submit"));
                } else {
                    console.log("QtKeychain: No credential selected");
                }
            }).catch(err => console.error("QtKeychain credential picker error:", err));
        };
        form.appendChild(pickBtn);
    }

    const actions = document.createElement('div');
    actions.className = 'actions';
    form.appendChild(actions);

    const submitBtn = document.createElement('button');
    submitBtn.type = 'submit';
    submitBtn.className = 'btn-primary';
    submitBtn.textContent = isWrite ? 'Save' : 'Sign In';
    actions.appendChild(submitBtn);

    const cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.className = 'btn-secondary';
    cancelBtn.textContent = 'Cancel';
    actions.appendChild(cancelBtn);

    document.body.appendChild(overlay);
    if (keyStr && !isWrite) {
        passInput.focus();
    } else {
        userInput.focus();
    }

    const cleanup = () => {
        if (overlay.parentNode) document.body.removeChild(overlay);
    };

    const finish = (type, data, code) => {
        cleanup();
        if (type === 'error') {
            const errorStr = data ? (data.message || data.toString()) : "Unknown error";
            console.error("QtKeychain error:", errorStr, "Code:", code);
            const len = lengthBytesUTF8(errorStr) + 1;
            const buffer = _malloc(len);
            stringToUTF8(errorStr, buffer, len);
            _qtkeychain_error(job, code, buffer);
            _free(buffer);
        } else if (type === 'read') {
            const len = lengthBytesUTF8(data) + 1;
            const buffer = _malloc(len);
            stringToUTF8(data, buffer, len);
            _qtkeychain_read_password_success(job, buffer, len - 1);
            _free(buffer);
        } else {
            _qtkeychain_write_password_success(job);
        }
    };

    cancelBtn.onclick = () => finish('error', "User cancelled", accessDeniedByUser);

    form.onsubmit = (e) => {
        const username = userInput.value;
        const password = passInput.value;
        if (isWrite) {
            const useStore = navigator.credentials && navigator.credentials.store && typeof PasswordCredential !== 'undefined';
            if (useStore) {
                if (e && e.preventDefault) e.preventDefault();
                navigator.credentials.store(new PasswordCredential({ id: username, password: password, name: username }))
                .finally(() => finish('write'));
            } else {
                setTimeout(() => finish('write'), 100);
            }
        } else {
            if (e && e.preventDefault) e.preventDefault();
            password ? finish('read', password) : finish('error', "Password cannot be empty", entryNotFound);
        }
    };
});

}

void ReadPasswordJobPrivate::scheduledStart()
{
    show_bridge_form(this, service.toUtf8().constData(), key.toUtf8().constData(), "", false, EntryNotFound, AccessDeniedByUser, OtherError);
}

void WritePasswordJobPrivate::scheduledStart()
{
    show_bridge_form(this, service.toUtf8().constData(), key.toUtf8().constData(), data.constData(), true, EntryNotFound, AccessDeniedByUser, OtherError);
}

void DeletePasswordJobPrivate::scheduledStart()
{
    q->emitFinishedWithError(NotImplemented, "Delete is not supported by browser sandboxes");
}

bool QKeychain::isAvailable()
{
    return true;
}
