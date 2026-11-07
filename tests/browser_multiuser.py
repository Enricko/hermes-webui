#!/usr/bin/env python3
"""Real browser/UI acceptance on a new disposable installation, never a live URL.

Requires the same image/evidence env vars and sudo as test_multiuser_docker.py,
plus Playwright/Chromium. Run: .venv/bin/python tests/browser_multiuser.py
"""

import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from multiuser_lab import Lab


async def run():
    from playwright.async_api import async_playwright
    evidence = Path(os.environ.get('HERMES_MULTIUSER_EVIDENCE', '/tmp/hermes-multiuser-browser'))
    evidence.mkdir(parents=True, exist_ok=True)
    lab = Lab(os.environ['HERMES_MULTIUSER_TEST_IMAGES'], evidence)
    failures = []
    statuses = []
    profile_switch_seconds = []
    try:
        await lab.start()
        # Reproduce the real report: an admin has a second assigned profile,
        # while the worker itself still has only its default filesystem profile.
        status, _ = await lab.api('administrator', '/multiuser/api/users/' + lab.users['administrator']['id'],
            {'template_ids':[lab.template, lab.discovered_template], 'provider_ids':[p['provider_id'] for p in lab.connections],
             'template_id':lab.template, 'provider_id':lab.provider})
        assert status == 200
        await lab.login('administrator', fresh=True)
        await lab.ready(['administrator'])
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                for label, width, height in [('desktop', 1440, 1000), ('narrow', 760, 1000), ('mobile', 390, 844)]:
                    context = await browser.new_context(viewport={'width': width, 'height': height})
                    page = await context.new_page()
                    page.on('pageerror', lambda error: failures.append(str(error)))
                    page.on('response', lambda response: statuses.append((response.status, response.url)) if response.status >= 400 else None)
                    await page.goto(lab.origin + '/login')
                    await page.screenshot(path=str(evidence / (label + '-login.png')))
                    assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    await page.locator('#mu-username').fill('administrator')
                    await page.locator('#mu-password').fill(lab.passwords['administrator'])
                    await page.locator('#mu-sign-in').click()
                    await page.wait_for_url(lab.origin + '/')
                    await page.locator('#mu-account').wait_for(state='attached')
                    await page.wait_for_timeout(2000)
                    assert await page.locator('#msg').count() == 1
                    assert not await page.get_by_text('This tab is running a different WebUI version.', exact=False).is_visible()
                    # Original upstream chrome without the additive account bar:
                    # visual reference only; not a second security implementation.
                    reference_style = await page.add_style_tag(content='#mu-account{visibility:hidden!important}')
                    await page.screenshot(path=str(evidence / (label + '-upstream-chrome.png')))
                    await reference_style.evaluate('(node)=>node.remove()')
                    await page.screenshot(path=str(evidence / (label + '-chat.png')))
                    if not await page.locator('.nav-tab[data-panel="profiles"]:visible').count():
                        await page.locator('#btnHamburger').click()
                    await page.locator('.nav-tab[data-panel="profiles"]:visible').first.click()
                    await page.locator(f'#profilesPanel [data-account-profile="{lab.template}"]').click()
                    await page.locator('#profileDetailBody').get_by_text('Configured by account administrator', exact=True).wait_for()
                    assert '2 / 2' in await page.locator('#profileDetailBody').inner_text()
                    # Selecting a profile closes the phone drawer immediately;
                    # its closing animation can still make is_visible() true.
                    if width <= 640 or not await page.locator('#profilesPanel').is_visible():
                        await page.locator('#btnHamburger').click()
                    await page.evaluate('() => loadProfilesPanel()')
                    if width <= 640:
                        assert await page.evaluate('() => document.querySelector(".sidebar").classList.contains("mobile-open")')
                    assert await page.locator('#profilesPanel [data-account-profile]').count() == 2
                    assert not await page.locator('#btnDeleteProfileDetail').is_visible()
                    assert await page.locator('.mu-selection-dialog').count() == 0
                    await page.screenshot(path=str(evidence / (label + '-profile-shared-skills.png')))
                    # Simulate a late legacy native render that only knows the
                    # physical default. The identity catalog restores both
                    # grants automatically, without another selection dialog.
                    await page.evaluate('''() => {
                        document.querySelector('#profilesPanel').innerHTML = '<div class="profile-card" data-name="default">default</div>';
                    }''')
                    await page.locator(f'#profilesPanel [data-account-profile="{lab.discovered_template}"]').wait_for(state='visible')
                    assert await page.locator('#profilesPanel [data-account-profile]').count() == 2
                    assert await page.locator('#profilesPanel [data-name="default"]').count() == 0
                    # Both directions use the same document, browser preferences
                    # and admitted worker. No reconcile call may hide a restart.
                    before_runtime = lab.runtime('administrator')['runtime_id']
                    before_version = lab.store.user(lab.users['administrator']['id'])['auth_version']
                    await page.evaluate('() => {window.__nativeSwitchCanary="same-document";localStorage.setItem("native-switch-preference","keep");}')
                    for target, name in [(lab.discovered_template, 'writer'), (lab.template, 'default')]:
                        if width <= 640 and not await page.evaluate('() => document.querySelector(".sidebar").classList.contains("mobile-open")'):
                            await page.locator('#btnHamburger').click()
                        started = time.monotonic()
                        await page.locator(f'#profilesPanel [data-account-profile="{target}"]').click()
                        await page.locator('#profileDetailTitle').get_by_text('Installed Hermes / '+name, exact=True).wait_for()
                        duration = time.monotonic() - started
                        profile_switch_seconds.append({'viewport':width, 'target':name, 'seconds':round(duration,3)})
                        assert duration < 10
                        assert await page.evaluate('() => window.__nativeSwitchCanary === "same-document" && localStorage.getItem("native-switch-preference") === "keep"')
                        assert lab.runtime('administrator')['runtime_id'] == before_runtime
                        assert lab.store.user(lab.users['administrator']['id'])['auth_version'] == before_version
                        assert await page.locator('#mu-waiting-title').count() == 0
                    await page.goto(lab.origin + '/')
                    if not await page.locator('.nav-tab[data-panel="chat"]:visible').count():
                        await page.locator('#btnHamburger').click()
                    await page.locator('.nav-tab[data-panel="chat"]:visible').first.click()
                    if width <= 640 and await page.evaluate('() => document.querySelector(".sidebar").classList.contains("mobile-open")'):
                        await page.get_by_role('button', name='Close menu', exact=True).click()
                    await page.locator('#profileChip').click()
                    dropdown = page.locator('#profileDropdown')
                    await dropdown.locator(f'[data-account-profile="{lab.discovered_template}"]').wait_for(state='visible')
                    assert await dropdown.locator('[data-account-profile]').count() == 2
                    await page.screenshot(path=str(evidence / (label + '-assigned-profile-dropdown.png')))
                    await page.keyboard.press('Escape')
                    catalog = await page.evaluate('fetch("/api/models/live").then(response=>response.json())')
                    assert {model['id'] for model in catalog['models']} >= {'fixture-model', 'fixture-extra'}
                    await page.goto(lab.origin + '/multiuser/admin')
                    dialog = page.locator('.mu-dialog')
                    await dialog.wait_for(state='visible')
                    await page.screenshot(path=str(evidence / (label + '-admin.png')))
                    await dialog.get_by_role('button', name='Hermes profiles', exact=True).click()
                    await dialog.get_by_text('Installed Hermes / default', exact=True).wait_for()
                    await dialog.get_by_text('Installed Hermes / writer', exact=True).wait_for()
                    await page.screenshot(path=str(evidence / (label + '-discovered-profiles.png')))
                    await dialog.get_by_role('button', name='Accounts', exact=True).click()
                    assert await dialog.evaluate('(node)=>node.getBoundingClientRect().right <= innerWidth')
                    await dialog.locator(f'.mu-person[data-user="{lab.users["alice"]["id"]}"]').click()
                    form = dialog.locator('.mu-account-editor')
                    await form.locator(f'[name=template_ids][value="{lab.discovered_template}"]').check()
                    for connection in lab.connections[1:]:
                        await form.locator(f'[name=provider_ids][value="{connection["provider_id"]}"]').uncheck()
                    assert await form.locator('[name=template_ids]:checked').count() == 2
                    assert await form.locator('[name=provider_ids]:checked').count() == 1
                    assert await form.locator('select').count() == 0
                    await form.locator(f'[name=template_ids_default][value="{lab.discovered_template}"]').check()
                    assert await form.locator('[name=template_ids]:checked').count() == 2
                    await page.screenshot(path=str(evidence / (label + '-multi-access.png')))
                    if label == 'desktop':
                        await dialog.get_by_role('button', name='New account', exact=True).click()
                        form = dialog.locator('.mu-account-editor')
                        await form.locator('[name=username]').fill('ui-created')
                        await form.locator('[name=password]').fill(secrets.token_urlsafe(24))
                        await form.locator(f'[name=template_ids][value="{lab.template}"]').check()
                        await form.locator(f'[name=template_ids][value="{lab.discovered_template}"]').check()
                        await form.get_by_role('button', name='Create account', exact=True).click()
                        await dialog.get_by_text('ui-created', exact=True).wait_for()
                        created = next(u for u in lab.store.users() if u['username'] == 'ui-created')
                        assert set(created['template_ids']) == {lab.template, lab.discovered_template}
                        assert created['provider_ids'] == [lab.provider]
                        await form.locator('summary').click()
                        await form.get_by_role('button', name='Disable account', exact=True).click()
                        await form.get_by_role('button', name='Enable account', exact=True, include_hidden=True).wait_for(state='attached')
                        await form.locator('summary').click()
                        await form.get_by_role('button', name='Enable account', exact=True).click()
                        await form.get_by_role('button', name='Disable account', exact=True, include_hidden=True).wait_for(state='attached')
                        independent = lab.connections[1]['provider_id']
                        await form.locator(f'[name=template_ids][value="{lab.discovered_template}"]').uncheck()
                        await form.locator(f'[name=provider_ids][value="{independent}"]').check()
                        await form.locator(f'[name=provider_ids_default][value="{independent}"]').check()
                        async with page.expect_response(lambda response: '/multiuser/api/users/' in response.url and response.request.method == 'POST') as assigned:
                            await form.get_by_role('button', name='Save access', exact=True).click()
                        assert (await assigned.value).status == 200
                        await dialog.get_by_text('Saved. Access changes are applied to the private workspace.', exact=True).wait_for()
                        created = next(user for user in lab.store.users() if user['username'] == 'ui-created')
                        assert created['template_id'] == lab.template and created['provider_id'] == independent
                        assert created['template_ids'] == [lab.template] and set(created['provider_ids']) == {lab.provider, independent}
                        await page.screenshot(path=str(evidence / 'desktop-account-provider.png'))
                        await dialog.locator('[name=account-search]').fill('ui-created')
                        assert await dialog.locator('.mu-person:visible').count() == 1
                        await dialog.locator('[name=account-search]').fill('')
                        await form.locator('summary').click()
                        await form.get_by_role('button', name='Disable account', exact=True).click()
                        for tab in ['Providers', 'Templates', 'Shared tools']:
                            await dialog.get_by_role('button', name=tab, exact=True).click()
                            await dialog.locator('form button[type=submit]').wait_for()
                    await dialog.get_by_role('button', name='Close', exact=True).click()
                    await page.goto(lab.origin + '/')
                    await page.locator('#mu-account').wait_for(state='attached')
                    await page.wait_for_function('() => typeof S !== "undefined" && S._bootReady')
                    sidebar_closed = await page.evaluate('innerWidth <= 640 ? !document.querySelector(".sidebar").classList.contains("mobile-open") : document.querySelector(".layout").classList.contains("sidebar-collapsed")')
                    if sidebar_closed:
                        if await page.locator('#btnHamburger').is_visible():
                            await page.locator('#btnHamburger').click()
                        else:
                            # Desktop uses the active Chat rail button to reopen
                            # its collapsed sidebar; the phone menu is hidden.
                            await page.locator('.nav-tab[data-panel="chat"]:visible').first.click()
                    if not await page.get_by_role('button', name='Sign out', exact=True).is_visible():
                        await page.screenshot(path=str(evidence / (label + '-logout-state.png')))
                        print('Logout state:', await page.evaluate('''() => ({url:location.href,
                          sidebar:document.querySelector('.sidebar')?.className,
                          inert:document.querySelector('.sidebar')?.inert,
                          layout:document.querySelector('.layout')?.className,
                          dialogs:Array.from(document.querySelectorAll('dialog[open]')).map(n=>n.className),
                          account:document.querySelector('#mu-account')?.innerText})'''))
                    await page.get_by_role('button', name='Sign out', exact=True).click()
                    await page.wait_for_url(lambda url: urlsplit(str(url)).path == '/login')
                    await context.close()
                # Exercise the unchanged composer/stream/upload flow as a regular
                # user, with another account's real conversation already present.
                bob_session = await lab.session('bobby')
                stream = await lab.start_chat('bobby', bob_session, 'B private browser canary')
                assert any(event == 'done' for event, _ in await lab.events('bobby', stream))
                context = await browser.new_context(viewport={'width': 1440, 'height': 1000})
                page = await context.new_page()
                page.on('pageerror', lambda error: failures.append(str(error)))
                page.on('response', lambda response: statuses.append((response.status, response.url)) if response.status >= 400 else None)
                await page.goto(lab.origin + '/login')
                await page.locator('#mu-username').fill('alice')
                await page.locator('#mu-password').fill(lab.passwords['alice'])
                await page.locator('#mu-sign-in').click()
                await page.wait_for_url(lab.origin + '/')
                await page.locator('#mu-account').wait_for(state='visible')
                assert not await page.get_by_role('button', name='Accounts', exact=True).count()
                await page.locator('#msg').fill('A private browser task')
                await page.locator('#btnSend').click()
                replies = page.locator('#messages').get_by_text('Hello from your private Hermes runtime.', exact=True)
                await replies.first.wait_for(timeout=60000)
                assert 'B private browser canary' not in await page.locator('body').inner_text()
                for _ in range(100):
                    if await page.evaluate('!S.busy && S.session && !S.session.active_stream_id'):
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError('The browser did not settle the owned streamed turn')
                # Upstream stages composer attachments, then uploads on Send.
                await page.locator('#fileInput').set_input_files({'name': 'ui-private.txt',
                    'mimeType': 'text/plain', 'buffer': b'Private browser attachment'})
                await page.get_by_text('ui-private.txt', exact=False).first.wait_for()
                await page.locator('#msg').fill('Read my private attachment')
                async with page.expect_response(lambda response: urlsplit(response.url).path == '/api/upload') as uploaded:
                    await page.locator('#btnSend').click()
                assert (await uploaded.value).status == 200
                await replies.nth(1).wait_for(timeout=60000)
                for _ in range(100):
                    if await page.evaluate('!S.busy && S.session && !S.session.active_stream_id'):
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError('The attachment turn did not settle')
                await page.screenshot(path=str(evidence / 'user-chat-upload.png'))
                # Reauthenticate directly in the same browser profile. Keeping
                # the public HTTP asset cache must not keep Alice's browser
                # storage or expose her conversation in Bobby's workspace.
                await page.evaluate('''async () => {
                  localStorage.setItem('private-account-canary', 'alice');
                  sessionStorage.setItem('private-account-canary', 'alice');
                  const cache = await caches.open('private-account-canary');
                  await cache.put('/private-account-canary', new Response('alice'));
                  await new Promise((resolve, reject) => {
                    const request = indexedDB.open('private-account-canary', 1);
                    request.onsuccess = () => { request.result.close(); resolve(); };
                    request.onerror = () => reject(request.error);
                  });
                }''')
                await page.goto(lab.origin + '/login')
                await page.locator('#mu-username').fill('bobby')
                await page.locator('#mu-password').fill(lab.passwords['bobby'])
                started = time.monotonic()
                async with page.expect_response(lambda response: urlsplit(response.url).path == '/api/auth/login') as signed_in:
                    await page.locator('#mu-sign-in').click()
                login_response = await signed_in.value
                assert login_response.status == 200
                assert (await login_response.all_headers())['clear-site-data'] == '"storage"'
                await page.wait_for_url(lab.origin + '/')
                await page.locator('#mu-account').wait_for(state='visible')
                switch_seconds = round(time.monotonic() - started, 3)
                assert 'bobby' in await page.locator('#mu-account').inner_text()
                assert 'A private browser task' not in await page.locator('body').inner_text()
                storage = await page.evaluate('''async () => ({
                  local: localStorage.getItem('private-account-canary'),
                  session: sessionStorage.getItem('private-account-canary'),
                  caches: await caches.keys(),
                  databases: (await indexedDB.databases()).map(db => db.name)
                })''')
                assert storage['local'] is None and storage['session'] is None
                assert 'private-account-canary' not in storage['caches']
                assert 'private-account-canary' not in storage['databases']
                private = await page.evaluate('''async () => {
                  const response = await fetch('/api/sessions');
                  return {cache: response.headers.get('cache-control'), body: await response.text()};
                }''')
                assert private['cache'] == 'no-store'
                assert 'A private browser task' not in private['body']
                await page.screenshot(path=str(evidence / 'same-profile-user-switch.png'))
                await context.close()
                # Prove the user's concrete independent-grants example, then
                # switch an assigned profile through the actual browser UI.
                for name, profiles, providers in [('alice', [lab.template, lab.discovered_template], [lab.provider]),
                    ('bobby', [lab.template], [lab.provider, lab.connections[1]['provider_id']])]:
                    status, _ = await lab.api('administrator', '/multiuser/api/users/' + lab.users[name]['id'],
                        {'template_ids':profiles, 'provider_ids':providers, 'template_id':lab.template, 'provider_id':lab.provider})
                    assert status == 200
                await lab.ready(['alice', 'bobby'])
                await lab.execute('alice', 'from pathlib import Path;Path("/workspace/profile-switch-canary").write_text("my saved work")')
                context = await browser.new_context(viewport={'width':1440, 'height':1000})
                page = await context.new_page()
                page.on('pageerror', lambda error: failures.append(str(error)))
                await page.goto(lab.origin + '/login')
                await page.locator('#mu-username').fill('alice'); await page.locator('#mu-password').fill(lab.passwords['alice'])
                await page.locator('#mu-sign-in').click(); await page.wait_for_url(lab.origin + '/')
                # Activate through the primary Profiles menu, not a separate
                # shortcut that could mask a missing assigned-profile entry.
                await page.locator('.nav-tab[data-panel="profiles"]:visible').first.click()
                assert await page.locator('#profilesPanel [data-account-profile]').count() == 2
                await page.screenshot(path=str(evidence / 'regular-user-assigned-switcher.png'))
                async with page.expect_response(lambda r: '/multiuser/api/selection' in r.url) as switched:
                    await page.locator(f'#profilesPanel [data-account-profile="{lab.discovered_template}"]').click()
                assert (await switched.value).status == 200
                assert (await switched.value).request.post_data_json == {'template_id':lab.discovered_template, 'provider_id':lab.provider, 'native':True}
                await page.wait_for_function('() => Boolean(document.querySelector("#mu-base-profile")?.textContent.includes("Installed Hermes / writer"))', timeout=60000)
                await page.locator('#profileDetailTitle').get_by_text('Installed Hermes / writer', exact=True).wait_for()
                assert '/login' not in page.url
                assert await page.locator('.mu-selection-dialog').count() == 0
                assert 'my saved work' in await lab.execute('alice', 'from pathlib import Path;print(Path("/workspace/profile-switch-canary").read_text())')
                if not await page.locator('#profilesPanel').is_visible():
                    await page.locator('.nav-tab[data-panel="profiles"]:visible').first.click()
                current_profile = page.locator(f'#profilesPanel [data-account-profile="{lab.discovered_template}"]')
                await current_profile.locator('.mu-profile-active').wait_for(state='visible')
                await current_profile.click()
                assert not await page.locator('#btnActivateProfileDetail').is_visible()
                assert not await page.locator('#btnDeleteProfileDetail').is_visible()
                # B has only the first profile. Its API must not gain A's grant.
                await lab.login('bobby', fresh=True)
                status, bob_profiles = await lab.api('bobby', '/api/profiles')
                assert status == 200 and [p['id'] for p in bob_profiles['account_profiles']] == [lab.template]
                await page.screenshot(path=str(evidence / 'regular-user-switched-profile.png'))
                await page.locator('.nav-tab[data-panel="chat"]:visible').first.click()
                before_requests = len(lab.model.requests)
                await page.locator('#msg').fill('Chat with the prepared writer profile')
                await page.locator('#btnSend').click()
                await page.locator('#messages').get_by_text('Hello from your private Hermes runtime.', exact=True).first.wait_for(timeout=60000)
                # Title/summary calls can follow a chat reply. Check the actual
                # tool-capable Agent request rather than whichever auxiliary
                # request happens to finish last.
                turns = [r for r in lab.model.requests[before_requests:] if r['tools']]
                assert turns and all(r['temperature'] == 0.45 and r['user_id'] == lab.users['alice']['id'] for r in turns)
                await context.close()
                assert not failures, failures
                assert not statuses, statuses
            finally:
                await browser.close()
        lab.results['browser_desktop_narrow_mobile_login_admin_logout'] = True
        lab.results['regular_user_browser_chat_stream_upload_and_private_history'] = True
        (evidence / 'browser-acceptance.json').write_text(json.dumps({'viewports': [1440, 760, 390],
            'uncaught_errors': failures, 'http_errors': statuses, 'result': 'pass',
            'regular_user_chat_stream_and_attachment_reply': True,
            'same_profile_user_switch_clears_private_browser_storage': True,
            'same_profile_user_switch_seconds': switch_seconds,
            'shared_base_profile_and_independent_account_provider_ui': True,
            'profile_shared_skill_counts_and_complete_provider_catalog': True,
            'independent_multiple_profile_provider_assignments_and_self_switch': True,
            'assigned_profiles_in_primary_panel_and_dropdown': True,
            'one_click_activation_preserves_current_provider_without_picker': True,
            'identity_restores_full_assigned_catalog_after_late_native_render': True,
            'native_switch_keeps_document_preferences_container_and_auth_generation': True,
            'native_profile_switch_seconds': profile_switch_seconds,
            'before_reference': 'same upstream chrome with only the additive account bar visually hidden'}, indent=2) + '\n')
    finally:
        await lab.close()


if __name__ == '__main__':
    asyncio.run(run())
