/******************************************************************************
 *   Copyright (C) 2026 Nils Schimmelmann <nschimme@gmail.com>                *
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
void qtkeychain_read_password_success(JobPrivate *job, const char *data, int length)
{
    if (job) {
        job->data = QByteArray(data, length);
        job->q->emitFinished();
    }
}

EMSCRIPTEN_KEEPALIVE
void qtkeychain_write_password_success(JobPrivate *job)
{
    if (job)
        job->q->emitFinished();
}

EMSCRIPTEN_KEEPALIVE
void qtkeychain_error(JobPrivate *job, int error, const char *errorString)
{
    if (job)
        job->q->emitFinishedWithError(static_cast<Error>(error), QString::fromUtf8(errorString));
}
}

namespace {

EM_JS(void, show_bridge_form,
      (JobPrivate * job, const char *service, const char *key, const char *data, bool isWrite,
       int entryNotFound, int accessDeniedByUser),
      {
          const serviceStr = UTF8ToString(service);
          const keyStr = UTF8ToString(key);
          const dataStr = UTF8ToString(data);

          const toCStr = (str) => {
              const len = lengthBytesUTF8(str) + 1;
              const ptr = _malloc(len);
              stringToUTF8(str, ptr, len);
              const res = { ptr: ptr, len: len - 1 };
              return res;
          };

          if (!document.getElementById("qtk-styles")) {
              const style = document.createElement("style");
              style.id = "qtk-styles";
              style.textContent =
                  "[id='qtk-overlay'] { position: fixed; inset: 0; background: rgba(0,0,0,0.5); "
                  "display: flex; justify-content: center; align-items: center; z-index: "
                  "2147483647; font-family: system-ui, sans-serif; } "
                  "[id='qtk-modal'] { background: #fff; padding: 24px; border-radius: 12px; "
                  "box-shadow: 0 8px 30px rgba(0,0,0,0.3); width: 320px; color: #333; } "
                  "[id='qtk-modal'] h2 { margin: 0 0 16px; font-size: 1.1em; font-weight: 600; } "
                  "[id='qtk-modal'] label { display: block; margin-bottom: 6px; font-size: 0.9em; "
                  "font-weight: 500; } "
                  "[id='qtk-modal'] input { width: 100%; margin-bottom: 16px; padding: 10px; "
                  "border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; font-size: "
                  "1em; } "
                  "[id='qtk-modal'] .actions { display: flex; flex-direction: row-reverse; gap: "
                  "8px; } "
                  "[id='qtk-modal'] button { flex: 1; padding: 10px; border-radius: 6px; border: "
                  "none; font-size: 1em; cursor: pointer; font-weight: 500; } "
                  ".qtk-primary { background: #007aff; color: #fff; } "
                  ".qtk-secondary { background: #e5e5ea; color: #333; } "
                  ".qtk-success { background: #28a745; color: #fff; margin-bottom: 16px; width: "
                  "100%; display: block; }";
              document.head.appendChild(style);
          }

          const overlay = document.createElement("div");
          overlay.id = "qtk-overlay";

          const formAttr = isWrite ? 'target="qtk-iframe" action="about:blank"' : "";
          const passAttr = isWrite ? "new-password" : "current-password";
          const submitLabel = isWrite ? "Save" : "Sign In";
          const extraHtml = isWrite ? '<iframe name="qtk-iframe" style="display:none"></iframe>' : "";

          overlay.innerHTML =
              '<div id="qtk-modal">' + '<h2 id="qtk-title"></h2>' + '<form id="qtk-form" ' +
              formAttr + ">" + '<label for="qtk-user">Username</label>' +
              '<input id="qtk-user" name="username" autocomplete="username">' +
              '<label for="qtk-pass">Password</label>' +
              '<input id="qtk-pass" type="password" name="password" autocomplete="' + passAttr +
              '">' + '<div id="qtk-extra"></div>' + '<div class="actions">' +
              '<button type="submit" class="qtk-primary">' + submitLabel + "</button>" +
              '<button type="button" id="qtk-cancel" class="qtk-secondary">Cancel</button>' +
              "</div>" + "</form>" + extraHtml + "</div>";
          document.body.appendChild(overlay);

          const form = overlay.querySelector("[id='qtk-form']");
          const userInput = overlay.querySelector("[id='qtk-user']");
          const passInput = overlay.querySelector("[id='qtk-pass']");

          overlay.querySelector("[id='qtk-title']").textContent = serviceStr;
          userInput.value = keyStr;
          if (isWrite)
              passInput.value = dataStr;

          const cleanup = () => overlay.remove();

          const finishWithError = (code, msg) => {
              cleanup();
              console.error("QtKeychain:", msg);
              const res = toCStr(msg);
              _qtkeychain_error(job, code, res.ptr);
              _free(res.ptr);
          };

          overlay.querySelector("[id='qtk-cancel']").onclick = () => {
              console.log("QtKeychain: Cancelled");
              finishWithError(accessDeniedByUser, "User cancelled");
          };

          const hasCreds = navigator.credentials && navigator.credentials.get &&
              (typeof PasswordCredential !== "undefined");
          if (!isWrite && hasCreds) {
              const btn = document.createElement("button");
              btn.type = "button";
              btn.className = "qtk-success";
              btn.textContent = "Use a saved password...";
              btn.onclick = () => {
                  console.log("QtKeychain: Requesting credentials...");
                  navigator.credentials.get({ password: true })
                      .then(cred => {
                          if (cred) {
                              userInput.value = cred.id || "";
                              passInput.value = cred.password || "";
                              form.dispatchEvent(new Event("submit"));
                          }
                      })
                      .catch(err => console.error("QtKeychain:", err));
              };
              overlay.querySelector("[id='qtk-extra']").appendChild(btn);
          }

          form.onsubmit = (e) => {
              const hasStore = navigator.credentials && navigator.credentials.store &&
                  (typeof PasswordCredential !== "undefined");
              const useNativeStore = isWrite && hasStore;
              if (!isWrite || useNativeStore)
                  e.preventDefault();

              console.log("QtKeychain: Submitting...", { isWrite: isWrite, user: userInput.value });

              if (isWrite) {
                  const done = () => {
                      console.log("QtKeychain: Save complete");
                      cleanup();
                      _qtkeychain_write_password_success(job);
                  };
                  if (useNativeStore) {
                      navigator.credentials
                          .store(new PasswordCredential({
                              id: userInput.value,
                              password: passInput.value,
                              name: userInput.value
                          }))
                          .catch(err => console.error("QtKeychain:", err))
                          .finally(done);
                  } else {
                      setTimeout(done, 100);
                  }
              } else {
                  if (passInput.value) {
                      const res = toCStr(passInput.value);
                      cleanup();
                      _qtkeychain_read_password_success(job, res.ptr, res.len);
                      _free(res.ptr);
                  } else {
                      finishWithError(entryNotFound, "Password cannot be empty");
                  }
              }
          };

          const focusInput = (keyStr && !isWrite) ? passInput : userInput;
          focusInput.focus();
      });

} // namespace

void ReadPasswordJobPrivate::scheduledStart()
{
    show_bridge_form(this, service.toUtf8().constData(), key.toUtf8().constData(), "", false,
                     EntryNotFound, AccessDeniedByUser);
}

void WritePasswordJobPrivate::scheduledStart()
{
    show_bridge_form(this, service.toUtf8().constData(), key.toUtf8().constData(), data.constData(),
                     true, EntryNotFound, AccessDeniedByUser);
}

void DeletePasswordJobPrivate::scheduledStart()
{
    q->emitFinishedWithError(NotImplemented, "Delete is not supported by browser sandboxes");
}

bool QKeychain::isAvailable()
{
    return true;
}
