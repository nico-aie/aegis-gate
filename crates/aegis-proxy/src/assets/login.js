// Login page client — pure browser JS, no bundler.
// Posts JSON to /admin/login, handles 200 / 401 / 429 / 4xx, then
// navigates to ?next=… (defaulting to /dashboard/).  CSP is
// `script-src 'self'`, so this file must live at /admin/login.js
// served from the same origin.

(function () {
  var form = document.getElementById('login-form');
  var errEl = document.getElementById('login-error');
  var btn = document.getElementById('login-submit');
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

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    showError('');
    var user = (form.user.value || '').trim();
    var password = form.password.value || '';
    if (!user || !password) {
      showError('Username and password required');
      return;
    }
    btn.disabled = true;
    fetch('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ user: user, password: password }),
    })
      .then(function (r) {
        if (r.ok) {
          window.location.href = safeNextUrl();
          return null;
        }
        return r.json().catch(function () { return {}; }).then(function (body) {
          if (r.status === 429) {
            var retry = r.headers.get('retry-after') || '60';
            showError('Too many attempts. Try again in ' + retry + 's.');
          } else if (r.status === 401) {
            showError(body.message || 'Invalid username or password');
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
