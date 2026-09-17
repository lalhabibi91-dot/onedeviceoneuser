(() => {
  'use strict';

  /*
   * LIVE Rewards authentication adapter.
   *
   * The important fix: when this app is running on Render, authentication is
   * handled by the SAME Express server. The old version incorrectly called
   * The API is served by this same project at /api/auth/* and /api/users.
   *
   * If the frontend is hosted separately, set window.CASH_AUTH_SERVER before
   * this script loads to the URL of the auth server.
   */
  const AUTH_SERVER = (window.CASH_AUTH_SERVER || '').replace(/\/$/, '') || window.location.origin;

  const $ = (id) => document.getElementById(id);
  const loginOverlay = $('loginOverlay');
  const modePicker = $('liveModePicker');
  const loginForm = $('liveLoginForm');
  const modeContinueBtn = $('liveModeContinue');
  const backToModesBtn = $('liveBackToModes');
  const modeSelectedText = $('liveModeSelected');
  const selectedModeLabel = $('liveSelectedModeLabel');
  const modeOptions = document.querySelectorAll('.live-mode-option');
  const usernameInput = $('loginUsername');
  const passwordInput = $('loginPassword');
  const loginBtn = $('loginSubmitBtn');
  const loginError = $('loginError');
  const contactBtn = $('liveContactBtn');
  const adminModal = $('adminModalOverlay');
  const closeAdminBtn = $('closeAdminModal');
  const saveUserBtn = $('saveUserBtn');
  const usersList = $('usersListContainer');

  let currentUser = null;
  let expiryTimer = null;
  let statusTimer = null;
  let selectedMode = null;

  const MODE_KEY = 'cashAppPayMode';
  const DEFAULT_MODE = '3';
  const MODE_LABELS = { '1': 'Classic', '2': 'Pay Sheet', '3': 'Modern' };
  // Access-token fallback makes authentication stable across separate frontend/API
  // deployments where third-party cookies may be blocked by the browser.
  const TOKEN_KEY = 'cash_auth_access_token';

  const API = {
    login: '/api/auth/login',
    status: '/api/auth/status',
    logout: '/api/auth/logout',
    users: '/api/users'
  };

  const url = (path) => AUTH_SERVER + path;

  function clearAuthBootHide() {
    try { document.documentElement.classList.remove('auth-boot'); } catch (_) {}
  }

  function setLoginError(message = '') {
    if (loginError) loginError.textContent = message;
  }

  function setBusy(busy) {
    if (!loginBtn) return;
    loginBtn.disabled = busy;
    loginBtn.textContent = busy ? 'Checking…' : 'Log in';
  }

  function applySelectedMode(mode) {
    if (!['1','2','3'].includes(String(mode))) return false;
    selectedMode = String(mode);
    try { localStorage.setItem(MODE_KEY, selectedMode); } catch (_) {}
    modeOptions.forEach(option => {
      const active = option.dataset.mode === selectedMode;
      option.classList.toggle('active', active);
      option.setAttribute('aria-checked', active ? 'true' : 'false');
    });
    const label = MODE_LABELS[selectedMode];
    if (modeSelectedText) {
      modeSelectedText.textContent = `${label} mode selected`;
      modeSelectedText.classList.add('ready');
    }
    if (selectedModeLabel) selectedModeLabel.textContent = label;
    if (modeContinueBtn) modeContinueBtn.disabled = false;
    window.dispatchEvent(new CustomEvent('cashPayModeSelected', { detail: { mode: selectedMode, label } }));
    return true;
  }

  function showModePicker() {
    // NEVER open the mode picker while an authenticated session exists.
    // This is deliberately checked here as a final guard because navigation
    // and async auth checks can finish in a different order.
    if (currentUser || getAccessToken()) return;
    if (modePicker) modePicker.classList.remove('hidden');
    if (loginForm) loginForm.classList.add('hidden');
    // Mode 3 is the default for this build. Keep the existing mode picker/login
    // flow intact; only the initial mode selection is fixed to Mode 3.
    const stored = (() => { try { return localStorage.getItem(MODE_KEY); } catch (_) { return null; } })();
    const initialMode = ['1','2','3'].includes(stored) ? stored : DEFAULT_MODE;
    applySelectedMode(initialMode);
  }

  // The mode picker is an entry screen only. Once a user has authenticated,
  // it must never be shown again during navigation, payments, or session checks.
  function showCredentialLogin(message = '') {
    clearAuthBootHide();
    // Session expiry/conflict goes directly to credentials, never mode selection.
    if (modePicker) modePicker.classList.add('hidden');
    if (loginOverlay) loginOverlay.classList.remove('hidden');
    closeAdmin();
    const stored = (() => { try { return localStorage.getItem(MODE_KEY); } catch (_) { return null; } })();
    applySelectedMode(['1','2','3'].includes(stored) ? stored : DEFAULT_MODE);
    if (modePicker) modePicker.classList.add('hidden');
    if (loginForm) loginForm.classList.remove('hidden');
    if (message) setLoginError(message);
  }

  function showFreshLogin(message = '') {
    clearAuthBootHide();
    if (loginOverlay) loginOverlay.classList.remove('hidden');
    closeAdmin();
    showModePicker();
    if (message) setLoginError(message);
  }

  // Backward-compatible name used only for real session failures.
  // Session failures go directly to the credential form, never the mode picker.
  function showLogin(message = '') {
    showCredentialLogin(message);
  }

  function hideLogin() {
    if (loginOverlay) loginOverlay.classList.add('hidden');
  }

  function formatTime(ms) {
    if (!Number.isFinite(ms) || ms <= 0) return 'Access expired';
    const total = Math.floor(ms / 1000);
    const d = Math.floor(total / 86400);
    const h = Math.floor((total % 86400) / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (d) return `${d}d ${h}h left`;
    if (h) return `${h}h ${m}m left`;
    if (m) return `${m}m ${s}s left`;
    return `${s}s left`;
  }

  function showToast(text) {
    const toast = $('timePopup');
    const toastText = $('timePopupText');
    if (!toast || !toastText) return;
    toastText.textContent = text;
    toast.classList.remove('hidden');
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => toast.classList.add('hidden'), 4000);
  }

  function stopTimers() {
    if (expiryTimer) clearInterval(expiryTimer);
    if (statusTimer) clearInterval(statusTimer);
    expiryTimer = null;
    statusTimer = null;
  }

  async function checkActiveSession() {
    // The server is the source of truth for the single-device session.
    // If the same account logs in somewhere else, this browser's token is
    // invalidated and the old device is returned to the login form.
    if (!currentUser || currentUser.role === 'admin') return;

    try {
      const response = await fetch(url(API.status), {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
        headers: authHeaders({ 'Cache-Control': 'no-cache' })
      });
      const data = await readResponse(response);

      if (response.ok && data.authenticated) return;

      if (response.status === 401 || data.authenticated === false) {
        setAccessToken('');
        try { localStorage.removeItem('cash_auth_authenticated'); } catch (_) {}
        currentUser = null;
        stopTimers();
        showCredentialLogin(data.reason === 'signed_in_elsewhere'
          ? 'This account was signed in on another device.'
          : 'Your session has ended. Please log in again.');
        window.dispatchEvent(new CustomEvent('cashAuthChanged', { detail: null }));
      }
    } catch (_) {
      // Keep the dashboard during a temporary network interruption.
    }
  }

  function getExpiry(user) {
    if (!user) return null;
    const value = user.expiresAt ?? user.expires_at ?? user.expiry ?? null;
    if (!value) return null;
    const time = new Date(value).getTime();
    return Number.isFinite(time) ? time : null;
  }

  function normalizeUser(data) {
    const raw = data?.user || data || {};
    return {
      id: raw.id || raw._id || null,
      username: raw.username || '',
      role: raw.role || 'customer',
      expiresAt: getExpiry(raw),
      isActive: raw.isActive !== false && raw.is_active !== false,
    };
  }

  function startUserTimers(user) {
    stopTimers();
    const expiry = getExpiry(user);
    if (!user || user.role === 'admin' || !expiry) return;

    const tick = async () => {
      const left = expiry - Date.now();
      if (left <= 0) {
        stopTimers();
        currentUser = null;
        try { localStorage.removeItem('cash_auth_authenticated'); } catch (_) {}
        showCredentialLogin('Your access time has expired. Contact support to renew.');
        try { await fetch(url(API.logout), { method: 'POST', credentials: 'include', headers: authHeaders() }); } catch (_) {}
        setAccessToken('');
        window.dispatchEvent(new CustomEvent('cashAuthChanged', { detail: null }));
      }
    };

    tick();
    expiryTimer = setInterval(tick, 1000);

    // Recheck every few seconds so a second-device login logs this device out
    // promptly, without changing the payment/dashboard flow.
    statusTimer = setInterval(checkActiveSession, 5000);
  }

  async function readResponse(response) {
    let data = {};
    try { data = await response.json(); } catch (_) {}
    return data;
  }

  function getAccessToken() {
    try { return localStorage.getItem(TOKEN_KEY) || ''; } catch (_) { return ''; }
  }

  function setAccessToken(token) {
    try {
      if (token) localStorage.setItem(TOKEN_KEY, token);
      else localStorage.removeItem(TOKEN_KEY);
    } catch (_) {}
  }

  function authHeaders(extra = {}) {
    const headers = { ...extra };
    const token = getAccessToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }

  async function login() {
    if (!selectedMode) {
      const stored = (() => { try { return localStorage.getItem(MODE_KEY); } catch (_) { return null; } })();
      applySelectedMode(['1','2','3'].includes(stored) ? stored : DEFAULT_MODE);
    }
    const username = (usernameInput?.value || '').trim();
    const password = (passwordInput?.value || '').trim();

    if (!username || !password) {
      setLoginError('Enter your username and password.');
      return;
    }

    setBusy(true);
    setLoginError('');

    try {
      const response = await fetch(url(API.login), {
        method: 'POST',
        headers: authHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' }),
        credentials: 'include',
        body: JSON.stringify({ username, password, deviceId: getDeviceId() }),
        cache: 'no-store'
      });

      const data = await readResponse(response);

      if (!response.ok) {
        setLoginError(data.error || data.message || 'Invalid username or password.');
        return;
      }

      if (data.accessToken) setAccessToken(data.accessToken);
      currentUser = normalizeUser(data);
      try { localStorage.setItem('cash_auth_authenticated', 'true'); } catch (_) {}

      if (usernameInput) usernameInput.value = '';
      if (passwordInput) passwordInput.value = '';
      // Never leave the mode picker visible after authentication.
      if (modePicker) modePicker.classList.add('hidden');
      if (loginForm) loginForm.classList.add('hidden');
      hideLogin();
      setLoginError('');

      if (currentUser.role === 'admin') {
        openAdmin();
        showToast('Admin access');
      } else {
        startUserTimers(currentUser);
        const expiry = getExpiry(currentUser);
        if (expiry) showToast(`Official License: ${formatTime(expiry - Date.now())}`);
      }

      window.dispatchEvent(new CustomEvent('cashAuthChanged', { detail: currentUser }));
    } catch (err) {
      console.error('Remote login error:', err);
      setLoginError('Authentication server is unavailable. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  function getDeviceId() {
    const key = 'cash_auth_device_id';
    try {
      let id = localStorage.getItem(key);
      if (!id) {
        id = (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
        localStorage.setItem(key, id);
      }
      return id;
    } catch (_) {
      return `${Date.now()}-${Math.random()}`;
    }
  }

  function openAdmin() {
    if (!adminModal) return;
    adminModal.classList.add('open');
    adminModal.setAttribute('aria-hidden', 'false');
    loadUsers();
  }

  function closeAdmin() {
    if (!adminModal) return;
    adminModal.classList.remove('open');
    adminModal.setAttribute('aria-hidden', 'true');
  }

  async function loadUsers() {
    if (!usersList) return;
    usersList.innerHTML = '<div class="live-users-empty">Loading accounts…</div>';

    try {
      const response = await fetch(url(API.users), {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
        headers: authHeaders({ 'Cache-Control': 'no-cache' })
      });
      const data = await readResponse(response);

      if (!response.ok) {
        usersList.innerHTML = `<div class="live-users-empty">${escapeHtml(data.error || 'Unable to load accounts.')}</div>`;
        return;
      }

      const raw = Array.isArray(data.users) ? data.users : Array.isArray(data) ? data : [];
      const entries = raw
        .filter(user => (user?.role || 'customer') !== 'admin')
        .map(user => [user.username || user.id, user]);

      if (!entries.length) {
        usersList.innerHTML = '<div class="live-users-empty">No customer accounts yet.</div>';
        return;
      }

      usersList.innerHTML = '';
      entries.forEach(([username, user]) => {
        const row = document.createElement('div');
        row.className = 'live-user-row';
        const expiry = getExpiry(user);
        const left = expiry ? expiry - Date.now() : null;
        const status = expiry ? (left <= 0 ? 'Expired' : formatTime(left)) : 'Active';

        const info = document.createElement('div');
        info.innerHTML = `<div class="live-user-name">${escapeHtml(username)}</div><div class="live-user-meta">${escapeHtml(status)}</div>`;

        const del = document.createElement('button');
        del.className = 'live-delete';
        del.type = 'button';
        del.textContent = 'Delete';
        del.addEventListener('click', () => deleteUser(user.id));

        row.append(info, del);
        usersList.appendChild(row);
      });
    } catch (err) {
      console.error('Load users error:', err);
      usersList.innerHTML = '<div class="live-users-empty">Authentication server connection failed.</div>';
    }
  }

  async function createUser() {
    const username = ($('newUsername')?.value || '').trim();
    const password = ($('newPassword')?.value || '').trim();
    const duration = parseFloat($('expiryDuration')?.value || '0');
    const unit = $('expiryUnit')?.value || 'days';

    if (!username || !password || !Number.isFinite(duration) || duration <= 0) {
      alert('Please fill out all fields correctly.');
      return;
    }

    const multiplier = unit === 'days' ? 1440 : unit === 'hours' ? 60 : 1;
    const durationMinutes = Math.max(1, Math.round(duration * multiplier));

    saveUserBtn.disabled = true;
    saveUserBtn.textContent = 'Saving…';

    try {
      const response = await fetch(url(API.users), {
        method: 'POST',
        credentials: 'include',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ username, password, duration: durationMinutes })
      });
      const data = await readResponse(response);

      if (!response.ok) {
        alert(data.error || data.message || 'Unable to create account.');
        return;
      }

      $('newUsername').value = '';
      $('newPassword').value = '';
      $('expiryDuration').value = '1';
      await loadUsers();
    } catch (err) {
      console.error('Create user error:', err);
      alert('Authentication server connection failed.');
    } finally {
      saveUserBtn.disabled = false;
      saveUserBtn.textContent = 'Add Account';
    }
  }

  async function deleteUser(id) {
    if (!id) return alert('User ID is missing. Refresh the account list and try again.');
    if (!confirm('Delete this account?')) return;

    try {
      const response = await fetch(url(`${API.users}/${encodeURIComponent(id)}`), {
        method: 'DELETE',
        credentials: 'include',
        headers: authHeaders()
      });
      const data = await readResponse(response);
      if (!response.ok) {
        alert(data.error || data.message || 'Unable to delete account.');
        return;
      }
      await loadUsers();
    } catch (err) {
      console.error('Delete user error:', err);
      alert('Authentication server connection failed.');
    }
  }

  async function checkStatus() {
    try {
      const response = await fetch(url(API.status), {
        method: 'GET',
        credentials: 'include',
        cache: 'no-store',
        headers: authHeaders({ 'Cache-Control': 'no-cache' })
      });
      const data = await readResponse(response);

      if (response.ok && data.authenticated) {
        currentUser = normalizeUser(data);
        try { localStorage.setItem('cash_auth_authenticated', 'true'); } catch (_) {}
        if (modePicker) modePicker.classList.add('hidden');
        if (loginForm) loginForm.classList.add('hidden');
        hideLogin();
        if (currentUser.role === 'admin') openAdmin();
        else startUserTimers(currentUser);
        window.dispatchEvent(new CustomEvent('cashAuthChanged', { detail: currentUser }));
        return true;
      }

      // A real authentication failure clears the saved token. Do not do this
      // for a temporary server/network problem.
      if (response.status === 401 || data.authenticated === false) {
        setAccessToken('');
        try { localStorage.removeItem('cash_auth_authenticated'); } catch (_) {}
        currentUser = null;
        stopTimers();
        showLogin(data.reason === 'expired' ? 'Your access time has expired. Contact support to renew.' : '');
        return false;
      }

      if (!currentUser) {
        if (getAccessToken()) showCredentialLogin();
        else showFreshLogin();
      }
      return false;
    } catch (err) {
      console.warn('Auth status check failed temporarily:', err);
      // Keep an already authenticated UI alive during a transient network hiccup.
      // If a token exists, never replace the dashboard with the mode picker.
      if (!currentUser && !getAccessToken()) showFreshLogin();
      return false;
    }
  }

  async function logout() {
    try {
      await fetch(url(API.logout), { method: 'POST', credentials: 'include', headers: authHeaders() });
    } catch (_) {}
    setAccessToken('');
    clearAuthBootHide();
    try { localStorage.removeItem('cash_auth_authenticated'); } catch (_) {}
    currentUser = null;
    stopTimers();
    closeAdmin();
    showFreshLogin();
    setLoginError('');
    window.dispatchEvent(new CustomEvent('cashAuthChanged', { detail: null }));
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
      '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;'
    }[ch]));
  }

  window.cashAuth = {
    getUser: () => currentUser,
    logout,
    openAdmin,
    checkStatus
  };

  modeOptions.forEach(option => {
    option.addEventListener('click', () => applySelectedMode(option.dataset.mode));
  });
  modeContinueBtn?.addEventListener('click', () => {
    if (!selectedMode) return;
    if (modePicker) modePicker.classList.add('hidden');
    if (loginForm) loginForm.classList.remove('hidden');
    if (usernameInput) usernameInput.focus();
  });
  backToModesBtn?.addEventListener('click', () => {
    setLoginError('');
    if (loginForm) loginForm.classList.add('hidden');
    showModePicker();
  });

  contactBtn?.addEventListener('click', () => {
    window.open('https://instagram.com/tiktokpannel.seller', '_blank', 'noopener,noreferrer');
  });
  loginBtn?.addEventListener('click', login);
  passwordInput?.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
  usernameInput?.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
  closeAdminBtn?.addEventListener('click', closeAdmin);
  adminModal?.addEventListener('click', e => { if (e.target === adminModal) closeAdmin(); });
  saveUserBtn?.addEventListener('click', createUser);

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) checkActiveSession();
  });
  window.addEventListener('focus', () => checkActiveSession());

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && adminModal?.classList.contains('open')) closeAdmin();
  });

  // Check an existing server session first. If there is none, the login screen stays visible.
  checkStatus();
})();
