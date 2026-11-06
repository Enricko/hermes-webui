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
    try:
        await lab.start()
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
                    await page.goto(lab.origin + '/multiuser/admin')
                    dialog = page.locator('.mu-dialog')
                    await dialog.wait_for(state='visible')
                    await page.screenshot(path=str(evidence / (label + '-admin.png')))
                    assert await dialog.evaluate('(node)=>node.getBoundingClientRect().right <= innerWidth')
                    if label == 'desktop':
                        form = dialog.locator('form')
                        await form.locator('[name=username]').fill('ui-created')
                        await form.locator('[name=password]').fill(secrets.token_urlsafe(24))
                        await form.get_by_role('button', name='Create account', exact=True).click()
                        await dialog.get_by_text('ui-created', exact=True).wait_for()
                        record = dialog.locator('.mu-record').filter(has=page.get_by_text('ui-created', exact=True))
                        await record.get_by_role('button', name='Disable', exact=True).click()
                        await record.get_by_role('button', name='Enable', exact=True).wait_for()
                        for tab in ['Providers', 'Templates', 'Shared tools']:
                            await dialog.get_by_role('button', name=tab, exact=True).click()
                            await dialog.locator('form button[type=submit]').wait_for()
                    await dialog.get_by_role('button', name='Close', exact=True).click()
                    await page.goto(lab.origin + '/')
                    await page.locator('#mu-account').wait_for(state='attached')
                    if await page.locator('#btnHamburger').is_visible():
                        await page.locator('#btnHamburger').click()
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
            'before_reference': 'same upstream chrome with only the additive account bar visually hidden'}, indent=2) + '\n')
    finally:
        await lab.close()


if __name__ == '__main__':
    asyncio.run(run())
