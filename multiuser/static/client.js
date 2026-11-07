(() => {
  'use strict';
  let identity;
  let dialog;
  let currentTab = 'users';
  let selectedAccount;
  let panelGeneration = 0;
  let pickerSequence = 0;
  let selectionBusy = false;
  let selectionDialog;
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
  function picker(parent, name, title, options, initial = [], defaultValue = '', multiple = true) {
    const group = element('fieldset', undefined, 'mu-picker');
    group.dataset.picker = name;
    const legend = element('legend', title); group.append(legend);
    const toolbar = element('div', undefined, 'mu-picker-toolbar');
    const count = element('small', '', 'mu-help'); toolbar.append(count); group.append(toolbar);
    const items = element('div', undefined, 'mu-choices');
    const rows = [];
    let active = defaultValue;
    function refresh() {
      const checked = rows.filter(row => row.input.checked);
      if (!checked.some(row => row.input.value === active)) active = checked[0]?.input.value || '';
      for (const row of rows) {
        row.card.classList.toggle('is-selected', row.input.checked);
        if (row.defaultInput) {
          row.defaultInput.checked = row.input.value === active;
          row.defaultLabel.hidden = !row.input.checked;
        }
      }
      count.textContent = `${checked.length} selected`;
    }
    function changed() { refresh(); group.dispatchEvent(new Event('change', {bubbles: true})); }
    if (multiple && options.length > 1) {
      toolbar.append(button('Select all', () => { rows.forEach(row => { row.input.checked = true; }); changed(); }),
        button('Clear', () => { rows.forEach(row => { row.input.checked = false; }); changed(); }));
    }
    if (options.length > 5) {
      const search = field(group, '', `Search ${title.toLowerCase()}`, 'search');
      search.removeAttribute('name');
      search.addEventListener('input', () => rows.forEach(row => { row.card.hidden = !row.search.includes(search.value.toLowerCase()); }));
    }
    group.append(items);
    for (const option of options) {
      const card = element('div', undefined, 'mu-choice');
      const label = element('label', undefined, 'mu-choice-label');
      const input = element('input'); input.type = multiple ? 'checkbox' : 'radio';
      input.name = name; input.value = option.id; input.checked = initial.includes(option.id);
      input.id = `mu-choice-${++pickerSequence}`;
      const copy = element('span', undefined, 'mu-choice-copy');
      copy.append(element('strong', option.name));
      if (option.description) copy.append(element('small', option.description));
      label.append(input, copy); card.append(label);
      const row = {card, input, search: `${option.name} ${option.description || ''}`.toLowerCase()};
      if (multiple) {
        row.defaultLabel = element('label', undefined, 'mu-default-choice');
        row.defaultInput = element('input'); row.defaultInput.type = 'radio';
        row.defaultInput.name = `${name}_default`; row.defaultInput.value = option.id;
        row.defaultLabel.append(row.defaultInput, element('span', 'Default'));
        row.defaultInput.addEventListener('change', event => { event.stopPropagation(); active = option.id; changed(); });
        card.append(row.defaultLabel);
      }
      input.addEventListener('change', event => { event.stopPropagation(); if (!multiple) active = option.id; changed(); });
      rows.push(row); items.append(card);
    }
    if (!options.length) group.append(element('p', 'No options available yet.', 'mu-help'));
    parent.append(group); refresh();
    return {group, values: () => rows.filter(row => row.input.checked).map(row => row.input.value),
      active: () => active, set: (values, current) => {
        rows.forEach(row => { row.input.checked = values.includes(row.input.value); });
        active = current || ''; changed();
      }};
  }
  function message(text, error = false) {
    const node = dialog.querySelector('.mu-status');
    node.textContent = text; node.classList.toggle('mu-error', error);
    node.scrollIntoView({block:'nearest'});
  }
  async function logout() {
    await request('/api/auth/logout', {});
    localStorage.clear(); sessionStorage.clear();
    location.replace('/login');
  }
  async function panel(tab = currentTab) {
    const generation = ++panelGeneration;
    currentTab = tab;
    if (!dialog) {
      dialog = element('dialog', undefined, 'mu-dialog');
      const header = element('div', undefined, 'mu-dialog-header');
      const title = element('h2', 'Accounts & access'); title.id = 'mu-admin-title';
      dialog.setAttribute('aria-labelledby', title.id);
      header.append(title, button('Close', () => dialog.close()));
      const nav = element('nav', undefined, 'mu-dialog-nav');
      for (const [key, label] of [['users', 'Accounts'], ['profiles', 'Hermes profiles'], ['providers', 'Providers'], ['templates', 'Templates'], ['tools', 'Shared tools']]) {
        const item = button(label, () => panel(key).catch(error => message(error.message, true)));
        item.dataset.tab = key; nav.append(item);
      }
      dialog.append(header, nav, element('div', undefined, 'mu-dialog-body'));
      document.body.append(dialog);
    }
    const body = dialog.querySelector('.mu-dialog-body');
    const status = element('div', '', 'mu-status'); status.setAttribute('role', 'status');
    body.replaceChildren(status);
    for (const item of dialog.querySelectorAll('[data-tab]')) item.setAttribute('aria-pressed', String(item.dataset.tab === tab));
    if (!dialog.open) dialog.showModal();
    const grid = element('div', undefined, 'mu-grid');
    const list = element('div', undefined, 'mu-list');
    const form = element('form', undefined, 'mu-form');
    grid.append(list, form); body.append(grid);
    let editing;
    let submit;
    let dirty = () => true;
    if (tab === 'users') {
      const [users, templates, providers, catalog] = await Promise.all([request('/multiuser/api/users'), request('/multiuser/api/templates'), request('/multiuser/api/providers'), request('/multiuser/api/hermes-profiles')]);
      if (generation !== panelGeneration) return;
      grid.classList.add('mu-accounts-grid'); list.classList.add('mu-account-list');
      if (selectedAccount === undefined) selectedAccount = users.users[0]?.id || null;
      const user = users.users.find(u => u.id === selectedAccount);
      selectedAccount = user?.id || null;
      const accountTitle = element('div', undefined, 'mu-section-title');
      accountTitle.append(element('h3', 'People'), element('small', `${users.users.length} accounts`, 'mu-help'));
      const openAccount = id => {
        selectedAccount = id;
        panel('users').then(() => {
          if (innerWidth <= 760) dialog.querySelector('.mu-account-editor')?.scrollIntoView({block:'start'});
        }).catch(e => message(e.message, true));
      };
      list.append(accountTitle, button('New account', () => openAccount(null)));
      const search = field(list, 'account-search', 'Search accounts', 'search');
      const accountRows = [];
      for (const account of users.users) {
        const row = button('', () => openAccount(account.id));
        row.className = 'mu-person'; row.dataset.user = account.id;
        row.setAttribute('aria-pressed', String(account.id === selectedAccount));
        row.append(element('strong', account.username), element('small', `${account.role === 'admin' ? 'Admin' : 'User'} · ${account.enabled ? account.runtime_state : 'Disabled'}`),
          element('small', `${account.template_ids.length} profiles · ${account.provider_ids.length} providers`));
        accountRows.push({row, name: account.username.toLowerCase()}); list.append(row);
      }
      search.addEventListener('input', () => accountRows.forEach(({row, name}) => { row.hidden = !name.includes(search.value.toLowerCase()); }));
      form.classList.add('mu-account-editor');
      const back = button('Back to People', () => list.scrollIntoView({block:'start'})); back.classList.add('mu-back-to-people'); form.append(back);
      form.append(element('h3', user ? `Edit ${user.username}` : 'Create account'),
        element('p', 'Check every profile and provider this person can use. Choose one default in each list. Conversations, memory and files stay private.', 'mu-help'));
      const username = field(form, 'username', 'Username', 'text', user?.username || '');
      username.required = true; username.readOnly = Boolean(user); username.autocomplete = 'off';
      if (!user) {
        const initialPassword = field(form, 'password', 'Initial password', 'password');
        initialPassword.required = true; initialPassword.minLength = 12;
        form.append(element('small', 'Use at least 12 characters.', 'mu-help'));
      }
      const role = picker(form, 'role', 'Role', [{id:'user', name:'User', description:'Personal chats and files'},
        {id:'admin', name:'Admin', description:'Manage people and shared access'}], [user?.role || 'user'], user?.role || 'user', false);
      const profileName = t => catalog.profiles.find(p => p.template_id === t.id)?.name || t.name;
      const available = templates.templates.filter(t => t.enabled).sort((a, b) => profileName(a).localeCompare(profileName(b)));
      const profiles = picker(form, 'template_ids', 'Profiles', available.map(t => ({id:t.id, name:profileName(t), description:'Agent instructions and skills'})),
        user?.template_ids || [], user?.template_id || '');
      const selectedProfile = () => available.find(t => t.id === profiles.active());
      const primary = user?.provider_id || selectedProfile()?.document.provider_id || '';
      const connections = picker(form, 'provider_ids', 'AI providers', providers.providers.filter(p => p.enabled).map(p => ({id:p.id, name:p.name,
        description:available.some(t => t.document.provider_id === p.id || t.document.connections.some(c => c.provider_id === p.id)) ? 'Models from this connection' : 'Use models supported by this connection'})),
        user?.provider_ids || [], primary);
      profiles.group.addEventListener('change', () => {
        if (!connections.values().length && selectedProfile()) connections.set([selectedProfile().document.provider_id]);
      });
      const payload = () => ({role:role.active(), template_ids:profiles.values(), provider_ids:connections.values(),
        template_id:profiles.active() || null, provider_id:connections.active() || null});
      const signature = data => JSON.stringify({...data, template_ids:[...data.template_ids].sort(), provider_ids:[...data.provider_ids].sort()});
      const original = user ? signature({role:user.role, template_ids:user.template_ids, provider_ids:user.provider_ids,
        template_id:user.template_id, provider_id:user.provider_id || available.find(t => t.id === user.template_id)?.document.provider_id || null}) : '';
      dirty = () => !user || !user.access_managed || signature(payload()) !== original;
      if (user) {
        const security = element('details', undefined, 'mu-security'); security.append(element('summary', 'Password & account status'));
        const reset = field(security, 'reset-password', 'New password', 'password'); reset.minLength = 12;
        const change = async changes => {
          await request(`/multiuser/api/users/${user.id}`, changes);
          if (user.id === identity.id) { location.replace('/login'); return; }
          await panel('users'); message('Account updated.');
        };
        security.append(button('Reset password', () => change({password:reset.value}).catch(e => message(e.message, true))),
          button(user.enabled ? 'Disable account' : 'Enable account', () => change({enabled:!user.enabled}).catch(e => message(e.message, true))));
        form.append(security);
        if (user.id === identity.id) form.append(element('p', 'Changing your own access will sign you out. Your saved work is preserved.', 'mu-help'));
        else form.append(element('p', 'Saving access signs this person out and restarts their agent. Saved chats and files are preserved.', 'mu-help'));
      }
      submit = async () => {
        const data = payload();
        if (data.template_ids.length && !data.provider_ids.length) throw new Error('Choose at least one AI provider for the assigned profiles.');
        if (user) await request(`/multiuser/api/users/${user.id}`, data);
        else {
          const created = await request('/multiuser/api/users', {...data, username:username.value, password:form.elements.password.value});
          selectedAccount = created.user.id;
        }
      };
    } else if (tab === 'profiles') {
      const value = await request('/multiuser/api/hermes-profiles');
      if (generation !== panelGeneration) return;
      grid.style.gridTemplateColumns = '1fr'; form.hidden = true;
      list.append(element('p', 'These are reusable Hermes capabilities. In Accounts, check the profiles and providers each person may use. Each person keeps private conversations, memory and files.', 'mu-help'));
      if (!value.profiles.length) {
        list.append(element('p', 'No Hermes installation connected. Run the operator connect-hermes setup described in docs/multiuser.md. Source folders can only be registered by the server operator.', 'mu-help'));
      }
      for (const profile of value.profiles) {
        const record = element('div', undefined, 'mu-record');
        record.append(element('strong', profile.name), element('small', `${profile.status} · ${profile.message}`));
        record.append(element('small', `Last checked: ${new Date(profile.updated * 1000).toLocaleString()}`));
        if (profile.template_id) record.append(button('Manage account access', () => panel('users').catch(e => message(e.message, true))));
        list.append(record);
      }
      return;
    } else if (tab === 'providers') {
      const value = await request('/multiuser/api/providers');
      if (generation !== panelGeneration) return;
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
      if (generation !== panelGeneration) return;
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
      if (generation !== panelGeneration) return;
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
    const save = element('button', tab === 'users' ? (selectedAccount ? 'Save access' : 'Create account') : 'Save', 'settings-action-btn primary');
    save.type = 'submit'; save.disabled = !dirty();
    const footer = element('div', undefined, 'mu-save-bar'); footer.append(save); form.append(footer);
    form.addEventListener('change', () => { save.disabled = !dirty(); });
    form.addEventListener('submit', async event => {
      event.preventDefault(); save.disabled = true;
      try { await submit(); await panel(); message('Saved. Access changes are applied to the private workspace.'); }
      catch (error) { message(error.message, true); }
      finally { save.disabled = false; }
    });
  }
  async function switchAccess() {
    if (selectionDialog?.open) { selectionDialog.focus(); return; }
    if (selectionBusy) return;
    selectionBusy = true;
    try { await refreshIdentity(); }
    finally { selectionBusy = false; }
    const modal = element('dialog', undefined, 'mu-dialog mu-selection-dialog');
    selectionDialog = modal;
    const title = element('h2', 'Your profiles & providers'); title.id = `mu-selection-${++pickerSequence}`;
    modal.setAttribute('aria-labelledby', title.id);
    const header = element('div', undefined, 'mu-dialog-header');
    header.append(title, button('Close', () => modal.close())); modal.append(header);
    const content = element('div', undefined, 'mu-selection-body'); modal.append(content);
    content.append(element('p', 'Choose from the access assigned to you. Switching restarts your private agent setup; saved chats and files stay available.', 'mu-help'));
    const profiles = picker(content, 'active-profile', 'Profile', identity.choices.profiles.map(p => ({id:p.id, name:p.name, description:'Agent instructions and skills'})),
      [identity.profile?.id], identity.profile?.id, false);
    const providers = picker(content, 'active-provider', 'AI provider', identity.choices.providers,
      [identity.provider?.id], identity.provider?.id, false);
    const status = element('p', '', 'mu-status'); status.setAttribute('role', 'status'); content.append(status);
    const apply = button('Use selection', async () => {
      apply.disabled = true;
      try {
        const value = await request('/multiuser/api/selection', {template_id:profiles.active(), provider_id:providers.active()});
        if (value.changed) { localStorage.clear(); sessionStorage.clear(); location.assign('/'); }
        else modal.close();
      } catch (error) { status.textContent = error.message; status.classList.add('mu-error'); apply.disabled = false; }
    });
    apply.classList.add('primary'); apply.disabled = !profiles.active() || !providers.active();
    content.append(apply);
    modal.addEventListener('close', () => modal.remove(), {once:true});
    document.body.append(modal); modal.showModal();
  }
  async function refreshIdentity() {
    identity = await request('/multiuser/api/me');
    const profile = document.getElementById('mu-base-profile');
    if (profile) profile.textContent = identity.profile ? `Profile: ${identity.profile.name} · Provider: ${identity.provider?.name || 'unavailable'}` : 'No base profile assigned';
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
      if (identity.choices.profiles.length && identity.choices.providers.length) bar.append(button('Profile & provider', () => switchAccess().catch(() => {})));
      bar.append(button('Sign out', () => logout().catch(() => location.replace('/login'))));
      const profile = element('small', '', 'mu-base-profile'); profile.id = 'mu-base-profile'; bar.append(profile);
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
