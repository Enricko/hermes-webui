(() => {
  'use strict';
  const form = document.getElementById('mu-login-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = document.getElementById('mu-sign-in');
    const error = document.getElementById('mu-login-error');
    const label = button.textContent;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    let navigating = false;
    button.disabled = true;
    button.textContent = 'Signing in…';
    error.hidden = true;
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, signal: controller.signal,
        body: JSON.stringify({username: form.elements.username.value, password: form.elements.password.value})
      });
      const data = await response.json();
      form.elements.password.value = '';
      if (!response.ok) throw new Error(data.error || 'Sign in failed');
      clearTimeout(timeout);
      button.textContent = 'Opening workspace…';
      // Local UI state is not an account database. Clear it on every identity
      // change so drafts/profile preferences cannot bleed into a later login.
      localStorage.clear();
      sessionStorage.clear();
      await Promise.all([
        'caches' in window ? caches.keys().then(keys => Promise.all(keys.map(key => caches.delete(key)))) : undefined,
        'serviceWorker' in navigator ? navigator.serviceWorker.getRegistrations().then(registrations =>
          Promise.all(registrations.map(registration => registration.unregister()))) : undefined
      ]);
      navigating = true;
      location.replace('/');
    } catch (failure) {
      error.textContent = failure.name === 'AbortError' ? 'Sign in timed out. Please try again.' : failure.message || 'Unable to connect';
      error.hidden = false;
    } finally {
      clearTimeout(timeout);
      if (!navigating) { button.disabled = false; button.textContent = label; }
    }
  });
})();
