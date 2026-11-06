(() => {
  'use strict';
  const title = document.getElementById('mu-waiting-title');
  const message = document.getElementById('mu-waiting-message');
  const error = document.getElementById('mu-waiting-error');
  const signOut = document.getElementById('mu-waiting-logout');
  let identity;
  let pending = false;
  let timer;
  async function check() {
    if (pending) return;
    pending = true;
    clearTimeout(timer);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch('/multiuser/api/me', {cache: 'no-store', signal: controller.signal});
      if (response.status === 401) { location.replace('/login'); return; }
      if (!response.ok) throw new Error('Unable to check your workspace. Trying again shortly.');
      identity = await response.json();
      error.hidden = true;
      signOut.disabled = false;
      document.getElementById('mu-waiting-identity').textContent = identity.username;
      document.getElementById('mu-manage-accounts').hidden = identity.role !== 'admin';
      const state = identity.runtime.state;
      if (state === 'ready') { location.reload(); return; }
      if (state === 'unassigned') {
        title.textContent = 'A capability template is needed';
        message.textContent = 'Ask your administrator to assign a template to your account. Your conversations and files stay private.';
      } else if (state === 'template_conflict' || state === 'error') {
        title.textContent = 'Your workspace needs administrator attention';
        message.textContent = state === 'template_conflict' ?
          'A template update needs review. Your private edits have been preserved.' :
          'The runtime could not start. Your administrator can check its status; your data has been preserved.';
      } else {
        title.textContent = 'Preparing your private workspace';
        message.textContent = 'Hermes is starting your tools, files and conversation storage. This page opens chat automatically when they are ready.';
      }
    } catch (failure) {
      error.textContent = failure.name === 'AbortError' ? 'The connection is slow. Checking again…' : failure.message;
      error.hidden = false;
    } finally {
      clearTimeout(timeout);
      pending = false;
      timer = setTimeout(check, 1500);
    }
  }
  document.getElementById('mu-waiting-retry').addEventListener('click', check);
  signOut.addEventListener('click', async () => {
    if (!identity) return;
    signOut.disabled = true;
    try {
      const response = await fetch('/api/auth/logout', {method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Hermes-CSRF-Token': identity.csrf_token}, body: '{}'});
      if (!response.ok && response.status !== 401) throw new Error('Sign out failed. Please retry.');
      localStorage.clear(); sessionStorage.clear();
      location.replace('/login');
    } catch (failure) {
      error.textContent = failure.message; error.hidden = false; signOut.disabled = false;
    }
  });
  window.addEventListener('pagehide', () => clearTimeout(timer));
  check();
})();
