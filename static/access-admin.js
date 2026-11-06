'use strict';
(function () {
function initializeAccessControls(host, options = {}) {
  if (host.dataset.accessInitialized) return;
  host.dataset.accessInitialized = '1';
  const $ = id => host.querySelector('#' + (options.prefix || '') + id);
  const root = options.root || new URL('../', location.href);
  const csrf = options.csrf || document.querySelector('meta[name="csrf-token"]')?.content || '';
  let data = null, selected = null, busy = false;
  const node = (tag, text) => { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; return element; };
  const notice = (message, error = false) => { $('notice').textContent = message; $('notice').className = error ? 'error' : 'success'; };
  function resourceFields(kind, binding={}) {
    $('template-label').hidden = !['profile','skill'].includes(kind);
    $('template-label').firstChild.textContent = kind === 'skill' ? 'Skill instructions' : 'Profile instructions';
    $('resource-content').value = kind === 'skill' ? binding.content || '' : binding.system_prompt || '';
    $('connection-settings').hidden = kind !== 'connection'; $('credential-label').hidden = kind !== 'connection';
    $('resource-url').required = kind === 'connection'; $('resource-account').required = kind === 'connection';
    $('resource-url').value = binding.base_url || ''; $('resource-account').value = binding.account_id || '';
    $('resource-protocol').value = binding.protocol || 'openai'; $('resource-credential').value = '';
    $('workspace-note').hidden = kind !== 'workspace';
  }
  async function request(path, body) {
    const response = await fetch(new URL(path, root), { credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-Hermes-CSRF-Token': csrf },
      ...(body ? { method: 'POST', body: JSON.stringify(body) } : {}) });
    if (response.status === 401) { location.replace(new URL('login', root)); throw new Error('Please sign in again.'); }
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Request failed.');
    return result;
  }
  async function mutate(action) {
    if (busy) return;
    busy = true;
    host.querySelectorAll('form button').forEach(button => { button.disabled = true; });
    try { await action(); } catch (error) { notice(error.message, true); }
    finally { busy = false; host.querySelectorAll('form button').forEach(button => { button.disabled = false; }); }
  }
  function choose(user) {
    selected = user || null;
    $('username').value = user?.username || '';
    $('username').readOnly = Boolean(user);
    $('role').value = user?.role || 'user';
    $('enabled').checked = user ? user.enabled : true;
    $('password').value = '';
    $('password').required = !user;
    $('save-account').textContent = user ? 'Save account' : 'Create account';
    $('grant-panel').hidden = !user || !user.enabled;
    renderGrants();
    host.querySelectorAll('.account').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.username === user?.username)));
  }
  function renderGrants() {
    $('grants').replaceChildren();
    if (!data || !selected) return;
    const grants = new Map(data.policy.grants.filter(grant => grant.account_id === selected.id).map(grant => [grant.resource_id, JSON.parse(grant.models)]));
    for (const kind of ['profile', 'workspace', 'connection', 'skill']) {
      const group = node('fieldset'); group.append(node('legend', {profile:'Profiles',workspace:'Private workspaces',connection:'Provider connections & models',skill:'Skills'}[kind]));
      for (const resource of data.policy.resources.filter(resource => resource.kind === kind)) {
        const label = node('label'); label.className = 'check';
        const check = node('input'); check.type = 'checkbox'; check.dataset.resourceId = resource.id; check.checked = grants.has(resource.id);
        label.append(check, node('span', resource.label)); group.append(label);
        if (kind === 'connection') {
          const models = node('label', 'Allowed models (one per line)'); models.className = 'model-label';
          const input = node('textarea'); input.rows = 3; input.dataset.modelsFor = resource.id; input.value = (grants.get(resource.id) || []).join('\n');
          input.disabled = !check.checked; check.addEventListener('change', () => { input.disabled = !check.checked; }); models.append(input); group.append(models);
        }
      }
      if (!group.querySelector('input')) group.append(node('p', 'No resources defined yet.'));
      $('grants').append(group);
    }
  }
  function render() {
    $('accounts').replaceChildren();
    for (const user of data.users) {
      const button = node('button'); button.type = 'button'; button.className = 'account'; button.dataset.username = user.username;
      button.append(node('strong', user.username), node('small', `${user.role === 'admin' ? 'Admin' : 'User'} · ${user.enabled ? 'Enabled' : 'Disabled'}`));
      button.addEventListener('click', () => choose(user)); $('accounts').append(button);
    }
    $('resources').replaceChildren();
    for (const resource of data.policy.resources) {
      const button = node('button', `${resource.label} · ${resource.kind} · ${resource.id}`); button.type = 'button';
      button.addEventListener('click', () => {
        $('resource-id').value = resource.id; $('resource-kind').value = resource.kind; $('resource-label').value = resource.label;
        resourceFields(resource.kind, JSON.parse(resource.binding)); $('resource-id').focus();
      }); $('resources').append(button);
    }
    choose(data.users.find(user => user.id === selected?.id));
  }
  async function load() { data = await request('api/admin/users'); render(); notice('Accounts and access loaded.'); }
  $('account-form').addEventListener('submit', event => {
    event.preventDefault(); mutate(async () => {
      const result = await request('api/admin/users', { action: selected ? 'update' : 'create', username: $('username').value.trim(),
        role: $('role').value, enabled: $('enabled').checked, ...($('password').value ? { password: $('password').value } : {}) });
      $('password').value = ''; selected = result.user; await load(); notice('Account saved.');
    });
  });
  $('grants-form').addEventListener('submit', event => {
    event.preventDefault(); if (!selected) return;
    mutate(async () => {
      const grants = {};
      for (const check of $('grants').querySelectorAll('input:checked')) {
        const input = [...$('grants').querySelectorAll('textarea')].find(element => element.dataset.modelsFor === check.dataset.resourceId);
        const models = input ? input.value.split('\n').map(model => model.trim()).filter(Boolean) : [];
        if (input && !models.length) throw new Error('Select at least one model for each provider connection.');
        grants[check.dataset.resourceId] = models;
      }
      await request('api/admin/access', { action: 'grants', account_id: selected.id, grants }); await load(); notice('Access saved.');
    });
  });
  $('resource-form').addEventListener('submit', event => {
    event.preventDefault(); mutate(async () => {
      const kind = $('resource-kind').value;
      const binding = kind === 'profile' ? {system_prompt:$('resource-content').value} : kind === 'skill' ? {content:$('resource-content').value}
        : kind === 'connection' ? {protocol:$('resource-protocol').value,base_url:$('resource-url').value.trim(),account_id:$('resource-account').value.trim()} : {};
      await request('api/admin/access', { action: 'resource', id: $('resource-id').value.trim(), kind: $('resource-kind').value,
        label: $('resource-label').value.trim(), binding, ...($('resource-credential').value ? {credential:$('resource-credential').value} : {}) });
      $('resource-credential').value = '';
      await load(); notice('Resource saved.');
    });
  });
  $('new-account').addEventListener('click', () => { choose(null); $('username').focus(); });
  $('resource-kind').addEventListener('change', () => {
    resourceFields($('resource-kind').value);
  });
  const reload = $('reload');
  if (reload) reload.addEventListener('click', () => { if (!busy) load().catch(error => notice(error.message, true)); });
  load().catch(error => notice(error.message, true));
}
window.initializeAccessControls = initializeAccessControls;
if (document.getElementById('account-form')) initializeAccessControls(document.body);
})();
