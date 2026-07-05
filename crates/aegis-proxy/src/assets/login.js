// Login page client — pure browser JS, no bundler.
// Posts JSON to /admin/login, handles 200 / 401 / 429 / 4xx, then
// navigates to ?next=… (defaulting to /dashboard/).  CSP is
// `script-src 'self'`, so this file must live at /admin/login.js
// served from the same origin.
//
// TOTP-5 — two additions over the original password-only client:
// 1. The form carries an optional `totp_code` field (enrolled accounts
//    must submit their app code with the password).
// 2. A 200 whose body says `enrollment_required: true` does NOT
//    redirect (that session can only reach the TOTP endpoints).
//    Instead: POST /api/admin/totp/enroll → render the inline-SVG QR +
//    manual-entry secret → the operator scans it with Google
//    Authenticator → POST /api/admin/totp/confirm with the app code →
//    on success the session is fully verified and we redirect to
//    ?next=. Both POSTs send the double-submit CSRF header read from
//    the JS-readable `aegis_csrf` cookie.

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
  if (!form || !errEl || !btn) return;

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

  function showError(msg) {
    errEl.textContent = msg;
  }

  function showEnrollError(msg) {
    if (enrollErrEl) enrollErrEl.textContent = msg;
  }

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

  // Switch the card from the sign-in form to the enrollment surface
  // and fetch the QR payload from the server.
  function startEnrollment() {
    if (!enrollSection || !enrollQr || !enrollSecret) {
      // Page shipped without the enrollment markup — fall back to an
      // actionable error instead of a dead redirect loop.
      showError('TOTP enrollment required — run `waf admin enroll-totp` or contact your operator.');
      return;
    }
    form.style.display = 'none';
    var title = document.querySelector('.login-card > h1');
    var subtitle = document.querySelector('.login-card > .subtitle');
    if (title) title.style.display = 'none';
    if (subtitle) subtitle.style.display = 'none';
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

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    showError('');
    var user = (form.user.value || '').trim();
    var password = form.password.value || '';
    var totpCode = (form.totp_code && form.totp_code.value || '').trim();
    if (!user || !password) {
      showError('Username and password required');
      return;
    }
    var payload = { user: user, password: password };
    if (totpCode) payload.totp_code = totpCode;
    btn.disabled = true;
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
            showError('Too many attempts. Try again in ' + retry + 's.');
          } else if (r.status === 401) {
            showError(body.message || 'Invalid username, password, or code');
          } else if (r.status === 400) {
            showError(body.message || 'Bad request');
          } else {
            showError(body.message || 'Login failed (' + r.status + ')');
          }
        });
      })
      .catch(function (e) {
        showError('Network error: ' + (e && e.message ? e.message : e));
      })
      .then(function () {
        btn.disabled = false;
      });
  });
})();
