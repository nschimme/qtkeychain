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

/*
 * hide_bridge_form: Closes the Bridge UI for a specific job.
 * This is used for lifecycle tracking: if the C++ Job object is destroyed
 * before the user interacts with the UI, we must close it to prevent
 * JavaScript callbacks from accessing a stale pointer.
 */
EM_JS(void, hide_bridge_form, (JobPrivate * job), {
    if (!window.qtk_active_jobs)
        return;
    const cleanup = window.qtk_active_jobs.get(job);
    if (cleanup) {
        cleanup();
        window.qtk_active_jobs.delete(job);
    }
});

/*
 * show_bridge_form: Displays a transient HTML modal (the "Bridge UI").
 * Browsers only offer to save credentials if they detect a form submission,
 * and secure APIs like 'navigator.credentials.store' require a user gesture.
 * To ensure compatibility with strict Content Security Policies (CSP), we use the
 * DOM API instead of 'innerHTML' or inline styles.
 */
EM_JS(void, show_bridge_form,
      (JobPrivate * job, const char *service, const char *key, const char *data, int dataLen,
       bool isWrite, int entryNotFound, int accessDeniedByUser),
      {
          const serviceStr = UTF8ToString(service);
          const keyStr = UTF8ToString(key);

          const toCStr = (str) => {
              const len = lengthBytesUTF8(str) + 1;
              const ptr = _malloc(len);
              if (!ptr)
                  return null;
              stringToUTF8(str, ptr, len);
              const res = { ptr: ptr, len: len - 1 };
              return res;
          };

          const createEl = (tag, parent, props, style) => {
              const el = document.createElement(tag);
              if (props)
                  Object.assign(el, props);
              if (style)
                  Object.assign(el.style, style);
              if (parent)
                  parent.appendChild(el);
              return el;
          };

          const overlay = createEl("div", document.body, { id: "qtk-overlay" }, {
              position: "fixed", inset: "0", background: "rgba(0,0,0,0.5)",
              display: "flex", justifyContent: "center", alignItems: "center",
              zIndex: "2147483647", fontFamily: "system-ui, sans-serif"
          });

          const modal = createEl("div", overlay, { id: "qtk-modal" }, {
              background: "#fff", padding: "24px", borderRadius: "12px",
              boxShadow: "0 8px 30px rgba(0,0,0,0.3)", width: "320px", color: "#333"
          });

          createEl("h2", modal, { id: "qtk-title", textContent: serviceStr },
                   { margin: "0 0 16px", fontSize: "1.1em", fontWeight: "600" });

          const form = createEl("form", modal, { id: "qtk-form" });
          if (isWrite) {
              form.target = "qtk-iframe";
              form.action = "about:blank";
          }

          const labelStyle = { display: "block", marginBottom: "6px", fontSize: "0.9em", fontWeight: "500" };
          const inputStyle = {
              width: "100%", marginBottom: "16px", padding: "10px",
              border: "1px solid #ccc", borderRadius: "6px", boxSizing: "border-box", fontSize: "1em"
          };

          createEl("label", form, { htmlFor: "qtk-user", textContent: "Username" }, labelStyle);
          const userInput = createEl("input", form, {
              id: "qtk-user", name: "username", autocomplete: "username", value: keyStr
          }, inputStyle);

          createEl("label", form, { htmlFor: "qtk-pass", textContent: "Password" }, labelStyle);
          const passInput = createEl("input", form, {
              id: "qtk-pass", type: "password", name: "password",
              autocomplete: isWrite ? "new-password" : "current-password"
          }, inputStyle);
          if (isWrite && dataLen > 0) {
              const dataBytes = HEAPU8.subarray(data, data + dataLen);
              passInput.value = new TextDecoder().decode(dataBytes);
          }

          const extraDiv = createEl("div", form, { id: "qtk-extra" });

          const actions = createEl("div", form, { className: "actions" },
                                   { display: "flex", flexDirection: "row-reverse", gap: "8px" });

          const btnStyle = {
              flex: "1", padding: "10px", borderRadius: "6px", border: "none",
              fontSize: "1em", cursor: "pointer", fontWeight: "500"
          };

          const submitBtn = createEl("button", actions, {
              type: "submit", className: "qtk-primary", textContent: isWrite ? "Save" : "Sign In"
          }, Object.assign({ background: "#007aff", color: "#fff" }, btnStyle));

          const cancelBtn = createEl("button", actions, {
              type: "button", id: "qtk-cancel", className: "qtk-secondary", textContent: "Cancel"
          }, Object.assign({ background: "#e5e5ea", color: "#333" }, btnStyle));

          if (isWrite) {
              createEl("iframe", modal, { name: "qtk-iframe" }, { display: "none" });
          }

          // We explicitly clear sensitive input values before removal to minimize
          // the window of exposure in browser memory.
          const cleanup = () => {
              userInput.value = "";
              passInput.value = "";
              overlay.remove();
              if (window.qtk_active_jobs)
                  window.qtk_active_jobs.delete(job);
          };

          if (!window.qtk_active_jobs)
              window.qtk_active_jobs = new Map();
          window.qtk_active_jobs.set(job, cleanup);

          const finishWithError = (code, msg) => {
              cleanup();
              console.error("QtKeychain:", msg);
              const res = toCStr(msg);
              if (res) {
                  _qtkeychain_error(job, code, res.ptr);
                  _free(res.ptr);
              } else {
                  _qtkeychain_error(job, code, 0);
              }
          };

          cancelBtn.onclick = () => {
              console.log("QtKeychain: Cancelled");
              finishWithError(accessDeniedByUser, "User cancelled");
          };

          const hasCreds = navigator.credentials && navigator.credentials.get &&
              (typeof PasswordCredential !== "undefined");
          if (!isWrite && hasCreds) {
              const btn = createEl("button", extraDiv, {
                  type: "button", className: "qtk-success", textContent: "Use a saved password..."
              }, {
                  background: "#28a745", color: "#fff", marginBottom: "16px",
                  padding: "10px", borderRadius: "6px", border: "none",
                  fontSize: "1em", cursor: "pointer", fontWeight: "500",
                  width: "100%", display: "block"
              });
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
                      if (res) {
                          _qtkeychain_read_password_success(job, res.ptr, res.len);
                          _free(res.ptr);
                      } else {
                          _qtkeychain_error(job, entryNotFound, 0);
                      }
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
    QObject::connect(this, &QObject::destroyed, [this] { hide_bridge_form(this); });
    show_bridge_form(this, service.toUtf8().constData(), key.toUtf8().constData(), "", 0, false,
                     EntryNotFound, AccessDeniedByUser);
}

void WritePasswordJobPrivate::scheduledStart()
{
    QObject::connect(this, &QObject::destroyed, [this] { hide_bridge_form(this); });
    show_bridge_form(this, service.toUtf8().constData(), key.toUtf8().constData(), data.constData(),
                     data.length(), true, EntryNotFound, AccessDeniedByUser);
}

void DeletePasswordJobPrivate::scheduledStart()
{
    q->emitFinishedWithError(NotImplemented, "Delete is not supported by browser sandboxes");
}

bool QKeychain::isAvailable()
{
    return true;
}
