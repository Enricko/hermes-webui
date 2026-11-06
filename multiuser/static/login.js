(() => {
  'use strict';
  const form = document.getElementById('mu-login-form');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = document.getElementById('mu-sign-in');
    const error = document.getElementById('mu-login-error');
    button.disabled = true;
    error.hidden = true;
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: form.elements.username.value, password: form.elements.password.value})
      });
      const data = await response.json();
      form.elements.password.value = '';
      if (!response.ok) throw new Error(data.error || 'Sign in failed');
      // Local UI state is not an account database. Clear it on every identity
      // change so drafts/profile preferences cannot bleed into a later login.
      localStorage.clear();
      sessionStorage.clear();
      if ('caches' in window) for (const key of await caches.keys()) await caches.delete(key);
      if ('serviceWorker' in navigator) for (const registration of await navigator.serviceWorker.getRegistrations()) await registration.unregister();
      location.replace('/');
    } catch (failure) {
      error.textContent = failure.message || 'Unable to connect';
      error.hidden = false;
    } finally {
      button.disabled = false;
    }
  });
})();
