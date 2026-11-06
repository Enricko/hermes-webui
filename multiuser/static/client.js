(() => {
  'use strict';
  let identity;
  let dialog;
  let currentTab = 'users';
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  async function request(path, data) {
    const options = data === undefined ? {} : {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-Hermes-CSRF-Token': identity.csrf_token},
      body: JSON.stringify(data)
    };
    const response = await fetch(path, options);
    if (response.status === 401) { location.replace('/login'); throw new Error('Session expired'); }
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || 'Request failed');
    return value;
  }
  function button(text, action) {
    const node = element('button', text, 'settings-action-btn');
    node.type = 'button';
    node.addEventListener('click', action);
    return node;
  }
  function field(form, name, label, type = 'text', value = '') {
    const wrapper = element('label', label);
    const input = element(type === 'textarea' ? 'textarea' : 'input');
    input.name = name;
    if (type !== 'textarea') input.type = type;
    input.value = value;
    if (type === 'password') input.autocomplete = 'new-password';
    wrapper.append(input); form.append(wrapper);
    return input;
  }
  function select(form, name, label, values, selected = '') {
    const wrapper = element('label', label);
    const input = element('select'); input.name = name;
    for (const [value, text] of values) {
      const option = element('option', text); option.value = value; input.append(option);
    }
    input.value = selected; wrapper.append(input); form.append(wrapper);
    return input;
  }
  function message(text, error = false) {
    const node = dialog.querySelector('.mu-status');
    node.textContent = text; node.classList.toggle('mu-error', error);
  }
  async function logout() {
    await request('/api/auth/logout', {});
    localStorage.clear(); sessionStorage.clear();
    location.replace('/login');
  }
  async function panel(tab = currentTab) {
    currentTab = tab;
    if (!dialog) {
      dialog = element('dialog', undefined, 'mu-dialog');
      const header = element('div', undefined, 'mu-dialog-header');
      header.append(element('h2', 'Accounts & shared capabilities'), button('Close', () => dialog.close()));
      const nav = element('nav', undefined, 'mu-dialog-nav');
      for (const [key, label] of [['users', 'Accounts'], ['providers', 'Providers'], ['templates', 'Templates'], ['tools', 'Shared tools']]) {
        nav.append(button(label, () => panel(key).catch(error => message(error.message, true))));
      }
      dialog.append(header, nav, element('div', undefined, 'mu-dialog-body'));
      document.body.append(dialog);
    }
    const body = dialog.querySelector('.mu-dialog-body');
    body.replaceChildren(element('div', '', 'mu-status'));
    if (!dialog.open) dialog.showModal();
    const grid = element('div', undefined, 'mu-grid');
    const list = element('div', undefined, 'mu-list');
    const form = element('form', undefined, 'mu-form');
    grid.append(list, form); body.append(grid);
    let editing;
    let submit;
    if (tab === 'users') {
      const [users, templates] = await Promise.all([request('/multiuser/api/users'), request('/multiuser/api/templates')]);
      field(form, 'username', 'Username').required = true;
      field(form, 'password', 'Initial password (at least 12 characters)', 'password').required = true;
      select(form, 'role', 'Role', [['user', 'User'], ['admin', 'Admin']], 'user');
      select(form, 'template_id', 'Capability template', [['', 'Assign later'], ...templates.templates.filter(t => t.enabled).map(t => [t.id, t.name])]);
      submit = async () => {
        const data = Object.fromEntries(new FormData(form)); data.template_id ||= null;
        await request('/multiuser/api/users', data);
      };
      for (const user of users.users) {
        const record = element('div', undefined, 'mu-record');
        record.append(element('strong', user.username), element('small', `${user.role} · ${user.enabled ? 'enabled' : 'disabled'} · ${user.runtime_state}`));
        const actions = element('div', undefined, 'mu-actions');
        const change = async (data) => {
          await request(`/multiuser/api/users/${user.id}`, data); await panel();
        };
        actions.append(button(user.enabled ? 'Disable' : 'Enable', () => change({enabled: !user.enabled}).catch(e => message(e.message, true))));
        actions.append(button(user.role === 'admin' ? 'Make user' : 'Make admin', () => change({role: user.role === 'admin' ? 'user' : 'admin'}).catch(e => message(e.message, true))));
        const template = select(record, 'assigned', 'Template', [['', 'Unassigned'], ...templates.templates.map(t => [t.id, t.name])], user.template_id || '');
        actions.append(button('Assign template', () => change({template_id: template.value || null}).catch(e => message(e.message, true))));
        const reset = field(record, 'reset-password', 'New password', 'password');
        actions.append(button('Reset password', async () => {
          try { await change({password: reset.value}); reset.value = ''; }
          catch (error) { message(error.message, true); }
        }));
        record.append(actions); list.append(record);
      }
    } else if (tab === 'providers') {
      const value = await request('/multiuser/api/providers');
      field(form, 'name', 'Provider name').required = true;
      field(form, 'base_url', 'OpenAI-compatible base URL (including /v1)', 'url').required = true;
      field(form, 'secret', 'API key (kept in the gateway; blank keeps an existing key)', 'password');
      form.append(element('p', 'Provider credentials are never copied into user runtimes.', 'mu-help'));
      submit = async () => {
        const data = Object.fromEntries(new FormData(form));
        if (editing) { data.id = editing; if (!data.secret) delete data.secret; }
        await request('/multiuser/api/providers', data);
      };
      for (const provider of value.providers) {
        const record = element('div', undefined, 'mu-record');
        record.append(element('strong', provider.name), element('small', provider.base_url));
        record.append(button('Edit', () => {
          editing = provider.id; form.elements.name.value = provider.name;
          form.elements.base_url.value = provider.base_url; form.elements.secret.value = '';
        }));
        list.append(record);
      }
    } else if (tab === 'templates') {
      const [value, providers, tools] = await Promise.all([request('/multiuser/api/templates'), request('/multiuser/api/providers'), request('/multiuser/api/tools')]);
      field(form, 'name', 'Template name').required = true;
      const provider = providers.providers[0];
      const example = {provider_id: provider ? provider.id : '', model: '', models: [], parameters: {max_tokens: 4096},
        agent: {max_iterations: 90}, soul: '', skills: {}, tools: [], egress_hosts: []};
      field(form, 'document', 'Capability document', 'textarea', JSON.stringify(example, null, 2));
      form.append(element('p', 'Select a provider ID, explicit model allowlist, SOUL, skill files and tool IDs. Personal memory/history and credentials are never imported.', 'mu-help'));
      const catalog = element('details'); catalog.append(element('summary', 'Available provider and shared tool IDs'));
      catalog.append(element('pre', JSON.stringify({providers: providers.providers.map(p => ({id:p.id,name:p.name})), tools: tools.tools.map(t => ({id:t.id,name:t.name}))}, null, 2)));
      form.append(catalog);
      submit = async () => {
        await request('/multiuser/api/templates', {id: editing, name: form.elements.name.value, document: JSON.parse(form.elements.document.value)});
      };
      for (const template of value.templates) {
        const record = element('div', undefined, 'mu-record');
        record.append(element('strong', template.name), element('small', `Version ${template.version} · ${template.document.model}`));
        record.append(button('Edit', () => {
          editing = template.id; form.elements.name.value = template.name;
          form.elements.document.value = JSON.stringify(template.document, null, 2);
        }));
        list.append(record);
      }
    } else {
      const value = await request('/multiuser/api/tools');
      field(form, 'name', 'Tool name').required = true;
      field(form, 'filename', 'Script filename').required = true;
      field(form, 'description', 'When to use it / input, output and temp arguments').required = true;
      field(form, 'content', 'Script source', 'textarea');
      form.append(element('p', 'Publish once. Assigned users read and execute the same version read-only; job data stays in their own workspace. Use the operator CLI to import an existing reviewed file.', 'mu-help'));
      submit = async () => {
        const data = Object.fromEntries(new FormData(form)); if (editing) data.id = editing;
        await request('/multiuser/api/tools', data);
      };
      for (const tool of value.tools) {
        const record = element('div', undefined, 'mu-record');
        record.append(element('strong', tool.name), element('small', `${tool.filename} · version ${tool.version}`));
        record.append(button('Edit', () => {
          editing = tool.id;
          for (const name of ['name', 'filename', 'description', 'content']) form.elements[name].value = tool[name];
        }));
        list.append(record);
      }
    }
    const save = element('button', tab === 'users' ? 'Create account' : 'Save', 'settings-action-btn primary');
    save.type = 'submit'; form.append(save);
    form.addEventListener('submit', async event => {
      event.preventDefault(); save.disabled = true;
      try { await submit(); await panel(); message('Saved. Private runtime changes are applied by the operator service.'); }
      catch (error) { message(error.message, true); }
      finally { save.disabled = false; }
    });
  }
  async function refreshIdentity() {
    identity = await request('/multiuser/api/me');
    const notice = document.getElementById('mu-runtime-notice');
    if (notice) {
      notice.hidden = identity.runtime.state === 'ready';
      notice.textContent = identity.runtime.state === 'unassigned' ? 'Ask your administrator to assign a capability template.' :
        identity.runtime.state === 'template_conflict' ? 'A template update needs review; your private edits were preserved.' :
        'Your private workspace is starting. You can keep this page open.';
    }
  }
  async function boot() {
    try {
      await refreshIdentity();
      const bar = element('div', undefined, 'mu-account');
      bar.id = 'mu-account';
      bar.append(element('span', identity.username + (identity.role === 'admin' ? ' · Admin' : ''), 'mu-account-name'));
      if (identity.role === 'admin') bar.append(button('Accounts', () => panel().catch(e => message(e.message, true))));
      bar.append(button('Sign out', () => logout().catch(() => location.replace('/login'))));
      const sidebar = document.querySelector('.sidebar');
      (sidebar || document.body).append(bar);
      const notice = element('div', '', 'mu-runtime-notice'); notice.id = 'mu-runtime-notice';
      document.body.append(notice); await refreshIdentity();
      // Account/provider credential management belongs to this gateway. Workers
      // still expose personal response/model controls inside their own state.
      for (const node of document.querySelectorAll('[data-settings-section="providers"],[data-settings-section="extensions"]')) node.hidden = true;
      if (location.pathname === '/multiuser/admin' && identity.role === 'admin') await panel();
      setInterval(() => refreshIdentity().catch(() => {}), 15000);
    } catch (error) {
      if (error.message !== 'Session expired') console.error('Account controls could not load');
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
