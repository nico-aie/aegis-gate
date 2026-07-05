// Login page client — pure browser JS, no bundler.
// CSP is `script-src 'self'`, so this file must live at
// /admin/login.js served from the same origin.
//
// TOTP-10 — two-step sign-in:
//   Step 1: username + password only.
//   Step 2: on a CODE-LESS 401 the #otp-modal dialog opens and asks for
//   the authenticator code, then retries the same credentials WITH the
//   code. The server deliberately answers wrong-password and
//   missing-code with one uniform envelope (F-CRITICAL-003 anti-oracle),
//   so the dialog is optimistic: a genuinely wrong password just fails
//   again inside the dialog, which offers "Back to password".
//
// TOTP-5 — first-login enrollment: a 200 with `enrollment_required:
// true` switches the card to the QR enrollment surface
// (POST /api/admin/totp/enroll → scan → POST /api/admin/totp/confirm),
// then redirects to ?next=. Both POSTs send the double-submit CSRF
// header read from the JS-readable `aegis_csrf` cookie.

(function () {
  var form = document.getElementById('login-form');
  var errEl = document.getElementById('login-error');
  var btn = document.getElementById('login-submit');
  var enrollSection = document.getElementById('enroll-section');
  var enrollForm = document.getElementById('enroll-form');
  var enrollErrEl = document.getElementById('enroll-error');
  var enrollBtn = document.getElementById('enroll-submit');
  var enrollQr = document.getElementById('enroll-qr');
  var enrollSecret = document.getElementById('enroll-secret');
  var enrollCopy = document.getElementById('enroll-copy');
  var enrollUser = document.getElementById('enroll-user');
  var otpModal = document.getElementById('otp-modal');
  var otpForm = document.getElementById('otp-form');
  var otpCode = document.getElementById('otp-code');
  var otpErrEl = document.getElementById('otp-error');
  var otpBtn = document.getElementById('otp-submit');
  var otpBack = document.getElementById('otp-back');
  var otpUser = document.getElementById('otp-user');
  if (!form || !errEl || !btn) return;

  // Credentials held between step 1 and step 2 (page-local, never
  // persisted).
  var pending = { user: '', password: '' };

  function safeNextUrl() {
    try {
      var params = new URLSearchParams(window.location.search);
      var next = params.get('next');
      if (next && next.charAt(0) === '/' && !next.startsWith('//')) {
        return next;
      }
    } catch (_) { /* ignore */ }
    return '/dashboard/';
  }

  function showError(msg) { errEl.textContent = msg; }
  function showOtpError(msg) { if (otpErrEl) otpErrEl.textContent = msg; }
  function showEnrollError(msg) { if (enrollErrEl) enrollErrEl.textContent = msg; }

  // Double-submit CSRF: the login response set the JS-readable
  // `aegis_csrf` cookie; the auth middleware requires the same value
  // echoed in the `x-csrf-token` header on every POST.
  function csrfToken() {
    var pairs = document.cookie.split(';');
    for (var i = 0; i < pairs.length; i++) {
      var p = pairs[i].trim();
      if (p.indexOf('aegis_csrf=') === 0) {
        return p.slice('aegis_csrf='.length);
      }
    }
    return '';
  }

  // ---- Step 2: OTP dialog --------------------------------------------

  function openOtpStep() {
    if (!otpModal || !otpCode) {
      // Dialog markup missing — degrade to an inline hint.
      showError('This account requires an authenticator code.');
      return;
    }
    showOtpError('');
    otpCode.value = '';
    if (otpUser) otpUser.textContent = pending.user;
    otpModal.className = 'open';
    otpCode.focus();
  }

  function closeOtpStep() {
    if (otpModal) otpModal.className = '';
    pending.password = '';
    var pw = document.getElementById('login-password');
    if (pw) { pw.value = ''; pw.focus(); }
  }

  if (otpBack) otpBack.addEventListener('click', closeOtpStep);

  // Code inputs accept digits only — pasted "123 456" or stray
  // characters from the authenticator app's copy button are cleaned
  // in place instead of failing the pattern check on submit.
  function digitsOnly(input) {
    if (!input) return;
    input.addEventListener('input', function () {
      var cleaned = input.value.replace(/\D/g, '');
      if (cleaned !== input.value) input.value = cleaned;
    });
  }
  digitsOnly(otpCode);
  digitsOnly(document.getElementById('enroll-code'));

  // ---- Enrollment surface ----------------------------------------------

  function startEnrollment() {
    if (!enrollSection || !enrollQr || !enrollSecret) {
      showError('TOTP enrollment required — run `waf admin enroll-totp` or contact your operator.');
      return;
    }
    if (otpModal) otpModal.className = '';
    form.style.display = 'none';
    var title = document.querySelector('.login-card > h1');
    var subtitle = document.querySelector('.login-card > .subtitle');
    if (title) title.style.display = 'none';
    if (subtitle) subtitle.style.display = 'none';
    if (enrollUser && pending.user) enrollUser.textContent = pending.user;
    enrollSection.style.display = 'block';

    fetch('/api/admin/totp/enroll', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': csrfToken(),
      },
      credentials: 'same-origin',
      body: '{}',
    })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) {
          if (!r.ok) {
            showEnrollError(body.message || 'Enrollment failed (' + r.status + ')');
            return;
          }
          // qr_svg is a server-rendered, self-contained inline SVG of
          // the otpauth:// URI (no external hosts). It contains no
          // user-controlled markup — the server built it from a secret
          // it generated itself.
          enrollQr.innerHTML = body.qr_svg || '';
          enrollSecret.textContent = body.secret_b32 || '';
          var codeInput = document.getElementById('enroll-code');
          if (codeInput) codeInput.focus();
        });
      })
      .catch(function (e) {
        showEnrollError('Network error: ' + (e && e.message ? e.message : e));
      });
  }

  if (enrollCopy && enrollSecret) {
    enrollCopy.addEventListener('click', function () {
      var key = enrollSecret.textContent || '';
      if (!key) return;
      var done = function () {
        enrollCopy.textContent = 'Copied';
        setTimeout(function () { enrollCopy.textContent = 'Copy'; }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(key).then(done).catch(function () { done(); });
      } else {
        // Clipboard API unavailable (plain-HTTP dev) — select the key
        // so a manual Ctrl/Cmd+C works.
        var range = document.createRange();
        range.selectNodeContents(enrollSecret);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        done();
      }
    });
  }

  if (enrollForm) {
    enrollForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      showEnrollError('');
      var code = (enrollForm.code.value || '').trim();
      if (!code) {
        showEnrollError('Enter the 6-digit code from the app');
        return;
      }
      if (enrollBtn) enrollBtn.disabled = true;
      fetch('/api/admin/totp/confirm', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': csrfToken(),
        },
        credentials: 'same-origin',
        body: JSON.stringify({ code: code }),
      })
        .then(function (r) {
          if (r.ok) {
            // Factor active + this session lifted to fully verified.
            window.location.href = safeNextUrl();
            return null;
          }
          return r.json().catch(function () { return {}; }).then(function (body) {
            if (r.status === 401) {
              showEnrollError(body.message || 'Code did not match — try the next one');
            } else if (r.status === 409) {
              showEnrollError(body.message || 'Enrollment expired — reload this page to restart');
            } else {
              showEnrollError(body.message || 'Confirm failed (' + r.status + ')');
            }
          });
        })
        .catch(function (e) {
          showEnrollError('Network error: ' + (e && e.message ? e.message : e));
        })
        .then(function () {
          if (enrollBtn) enrollBtn.disabled = false;
        });
    });
  }

  // ---- Login (both steps post here) ------------------------------------

  // `fromDialog` routes errors to the right surface: step-1 errors land
  // under the password form, step-2 errors inside the OTP dialog.
  function attemptLogin(code, fromDialog, submitBtn) {
    var payload = { user: pending.user, password: pending.password };
    if (code) payload.totp_code = code;
    if (submitBtn) submitBtn.disabled = true;
    var showErr = fromDialog ? showOtpError : showError;
    fetch('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    })
      .then(function (r) {
        if (r.ok) {
          return r.json().catch(function () { return {}; }).then(function (body) {
            if (body && body.enrollment_required) {
              startEnrollment();
            } else {
              window.location.href = safeNextUrl();
            }
          });
        }
        return r.json().catch(function () { return {}; }).then(function (body) {
          if (r.status === 429) {
            var retry = r.headers.get('retry-after') || '60';
            showErr('Too many attempts. Try again in ' + retry + 's.');
          } else if (r.status === 401) {
            if (!code && !fromDialog) {
              // Step 1 rejected without a code: either the password is
              // wrong or the account is enrolled and needs its code —
              // the envelope is uniform by design. Ask for the code;
              // a wrong password fails again inside the dialog.
              openOtpStep();
            } else {
              showErr('Invalid username, password, or authenticator code.');
            }
          } else if (r.status === 400) {
            showErr(body.message || 'Bad request');
          } else {
            showErr(body.message || 'Login failed (' + r.status + ')');
          }
        });
      })
      .catch(function (e) {
        showErr('Network error: ' + (e && e.message ? e.message : e));
      })
      .then(function () {
        if (submitBtn) submitBtn.disabled = false;
      });
  }

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    showError('');
    pending.user = (form.user.value || '').trim();
    pending.password = form.password.value || '';
    if (!pending.user || !pending.password) {
      showError('Username and password required');
      return;
    }
    attemptLogin('', false, btn);
  });

  if (otpForm) {
    otpForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      showOtpError('');
      var code = (otpCode && otpCode.value || '').trim();
      if (!code) {
        showOtpError('Enter the 6-digit code from your app');
        return;
      }
      attemptLogin(code, true, otpBtn);
    });
  }
})();
