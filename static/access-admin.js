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
  // Imported Hermes profiles carry their skills and SOUL (M4); show what a grant brings along.
  const profileSummary = binding => {
    if (!binding || binding.source !== 'hermes-profile') return '';
    const count = Array.isArray(binding.skills) ? binding.skills.length : 0;
    return `${count} skill${count === 1 ? '' : 's'}${binding.soul ? ' · SOUL' : ''}`;
  };
  function resourceFields(kind, binding={}) {
    $('template-label').hidden = !['profile','skill'].includes(kind);
    $('template-label').firstChild.textContent = kind === 'skill' ? 'Skill instructions' : 'Profile instructions';
    $('resource-content').value = kind === 'skill' ? binding.content || '' : binding.system_prompt || '';
    $('connection-settings').hidden = kind !== 'connection'; $('credential-label').hidden = kind !== 'connection';
    $('resource-url').required = kind === 'connection'; $('resource-account').required = kind === 'connection';
    $('resource-url').value = binding.base_url || ''; $('resource-account').value = binding.account_id || '';
    $('resource-protocol').value = binding.protocol || 'openai'; $('resource-credential').value = '';
    $('workspace-note').hidden = kind !== 'workspace';
    if ($('tool-settings')) {
      $('tool-settings').hidden = kind !== 'tool';
      $('resource-executable').value = binding.executable || '';
      $('resource-executable').required = kind === 'tool';
    }
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
    if ($('private-workspace')) $('private-workspace').textContent = user ? (user.workspace || '/' + user.username) : 'Created automatically from the login username';
    renderGrants();
    host.querySelectorAll('.account').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.username === user?.username)));
  }
  function renderGrants() {
    $('grants').replaceChildren();
    if (!data || !selected) return;
    const grants = new Map(data.policy.grants.filter(grant => grant.account_id === selected.id).map(grant => [grant.resource_id, JSON.parse(grant.models)]));
    for (const kind of ['profile', 'workspace', 'connection', 'skill', 'tool']) {
      const group = node('fieldset'); group.append(node('legend', {profile:'Profiles',workspace:'Private workspace',connection:'Provider connections & models',skill:'Extra skills',tool:'Approved installed tools (read only)'}[kind]));
      if (kind === 'profile') group.append(node('p', 'Each profile brings its own skills and SOUL.'));
      for (const resource of data.policy.resources.filter(resource => resource.kind === kind)) {
        const binding = JSON.parse(resource.binding);
        if (binding.available === false && !grants.has(resource.id)) continue;
        const label = node('label'); label.className = 'check';
        const check = node('input'); check.type = 'checkbox'; check.dataset.resourceId = resource.id; check.checked = grants.has(resource.id);
        const title = kind === 'workspace' ? '/' + selected.username : resource.label;
        label.append(check, node('span', title + (binding.available === false ? ' (unavailable)' : '')));
        if (kind === 'profile' && profileSummary(binding)) { const hint = node('small', profileSummary(binding)); hint.className = 'uac-hint'; label.append(hint); }
        group.append(label);
        if (kind === 'workspace' && binding.scope === 'login-username') {check.checked=true;check.disabled=true;}
        if (binding.available === false) {check.checked=false;check.disabled=true;}
        if (kind === 'connection') {
          const models = node('label', 'Allowed models (one per line)'); models.className = 'model-label';
          const input = node('textarea'); input.rows = 3; input.dataset.modelsFor = resource.id; input.value = (grants.get(resource.id) || []).join('\n');
          input.disabled = !check.checked; check.addEventListener('change', () => { input.disabled = !check.checked; }); models.append(input); group.append(models);
        }
      }
      if (!group.querySelector('input')) group.append(node('p', kind === 'workspace' ? `/${selected.username} · created automatically` : 'None defined yet.'));
      $('grants').append(group);
    }
    renderReferences();
  }
  function renderReferences() {
    // Read-only folder references: only the other login's private folder, never its conversations.
    const granted = new Set((data.policy.references || []).filter(row => row.account_id === selected.id).map(row => row.target_id));
    const policyAccounts = new Map(data.policy.accounts.map(account => [account.id, account]));
    const group = node('fieldset'); group.className = 'uac-wide'; group.append(node('legend', 'Folder references (read-only)'));
    group.append(node('p', 'Read-only access to the private folder of each selected login. Their conversations and other data stay private.'));
    for (const user of data.users.filter(user => user.id && user.id !== selected.id && policyAccounts.has(user.id))) {
      const enabled = user.enabled && Boolean(policyAccounts.get(user.id).enabled);
      const label = node('label'); label.className = 'check';
      const check = node('input'); check.type = 'checkbox'; check.dataset.referenceId = user.id;
      check.checked = enabled && granted.has(user.id); check.disabled = !enabled;
      label.append(check, node('span', (user.workspace || '/' + user.username) + (enabled ? '' : ' (disabled)'))); group.append(label);
    }
    if (!group.querySelector('input')) group.append(node('p', 'No other accounts yet.'));
    $('grants').append(group);
  }
  function render() {
    $('accounts').replaceChildren();
    for (const user of data.users) {
      const button = node('button'); button.type = 'button'; button.className = 'account'; button.dataset.username = user.username; button.dataset.enabled = String(Boolean(user.enabled));
      button.append(node('strong', user.username), node('small', `${user.role === 'admin' ? 'Admin' : 'User'} · ${user.enabled ? 'Enabled' : 'Disabled'}`));
      button.addEventListener('click', () => choose(user)); $('accounts').append(button);
    }
    $('resources').replaceChildren();
    for (const resource of data.policy.resources) {
      const binding = JSON.parse(resource.binding);
      if (binding.available === false) continue;
      if (resource.kind === 'profile' || (resource.kind === 'workspace' && binding.scope === 'login-username')) {
        const row = node('div'); row.className = 'resource-row';
        const summary = resource.kind === 'profile' ? profileSummary(binding) : '';
        row.append(node('strong', resource.label), node('small', resource.kind === 'profile'
          ? ['Hermes profile', summary, 'managed in Profiles'].filter(Boolean).join(' · ') : 'Automatic private folder'));
        $('resources').append(row);
        continue;
      }
      const kindLabel = {connection:'Provider connection',skill:'Skill',tool:'Installed tool',workspace:'Workspace'}[resource.kind] || resource.kind;
      const button = node('button'); button.type = 'button'; button.className = 'resource-row'; button.title = 'Edit this resource';
      button.append(node('strong', resource.label), node('small', `${kindLabel} · ${resource.id}`));
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
      for (const check of $('grants').querySelectorAll('input[data-resource-id]:checked')) {
        const input = [...$('grants').querySelectorAll('textarea')].find(element => element.dataset.modelsFor === check.dataset.resourceId);
        const models = input ? input.value.split('\n').map(model => model.trim()).filter(Boolean) : [];
        if (input && !models.length) throw new Error('Select at least one model for each provider connection.');
        grants[check.dataset.resourceId] = models;
      }
      const references = [...$('grants').querySelectorAll('input[data-reference-id]:checked')].map(check => check.dataset.referenceId);
      await request('api/admin/access', { action: 'grants', account_id: selected.id, grants, references }); await load(); notice('Access saved.');
    });
  });
  $('resource-form').addEventListener('submit', event => {
    event.preventDefault(); mutate(async () => {
      const kind = $('resource-kind').value;
      const binding = kind === 'profile' ? {system_prompt:$('resource-content').value} : kind === 'skill' ? {content:$('resource-content').value}
        : kind === 'connection' ? {protocol:$('resource-protocol').value,base_url:$('resource-url').value.trim(),account_id:$('resource-account').value.trim()}
        : kind === 'tool' ? {executable:$('resource-executable').value.trim()} : {scope:'login-username'};
      await request('api/admin/access', { action: 'resource', id: $('resource-id').value.trim(), kind: $('resource-kind').value,
        label: $('resource-label').value.trim(), binding, ...($('resource-credential').value ? {credential:$('resource-credential').value} : {}) });
      $('resource-credential').value = '';
      await load(); notice('Resource saved.');
    });
  });
  $('new-account').addEventListener('click', () => { choose(null); $('username').focus(); });
  // Preview the private folder a new login will receive; existing logins keep their stored path.
  $('username').addEventListener('input', () => {
    if (selected || !$('private-workspace')) return;
    const name = $('username').value.trim().toLowerCase();
    $('private-workspace').textContent = name ? '/' + name : 'Created automatically from the login username';
  });
  $('resource-kind').addEventListener('change', () => {
    resourceFields($('resource-kind').value);
  });
  const reload = $('reload');
  if (reload) reload.addEventListener('click', () => { if (!busy) load().catch(error => notice(error.message, true)); });
  if ($('import-profiles')) $('import-profiles').addEventListener('click', () => mutate(async () => {
    await request('api/admin/access',{action:'import_profiles'}); await load(); notice('Existing Hermes profiles refreshed. Choose which profiles to assign.');
  }));
  resourceFields($('resource-kind').value);
  load().catch(error => notice(error.message, true));
}
window.initializeAccessControls = initializeAccessControls;
if (document.getElementById('account-form')) initializeAccessControls(document.body);
})();
