#!/usr/bin/env python3
"""Cold, stale-generation and interrupted-boot logins recover automatically.

Uses the same explicit image/evidence variables and isolated Lab as the Docker
acceptance suite. Run with Playwright Chromium and the trusted test operator.
"""

import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from multiuser_lab import Lab


async def run():
    from playwright.async_api import async_playwright
    evidence = Path(os.environ.get('HERMES_MULTIUSER_EVIDENCE', '/tmp/hermes-startup-browser'))
    evidence.mkdir(parents=True, exist_ok=True)
    lab = Lab(os.environ['HERMES_MULTIUSER_TEST_IMAGES'], evidence)
    try:
        await lab.start()
        name = 'late-user'
        lab.passwords[name] = secrets.token_urlsafe(24)
        status, value = await lab.api('administrator', '/multiuser/api/users', {
            'username': name, 'password': lab.passwords[name], 'role': 'user', 'template_id': lab.template})
        assert status == 201
        lab.users[name] = value['user']
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                page = await browser.new_page(viewport={'width': 1280, 'height': 900})
                errors, requests = [], []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.on('request', lambda request: requests.append(request.url))
                await page.goto(lab.origin + '/login')
                await page.locator('#mu-username').fill(name)
                await page.locator('#mu-password').fill(lab.passwords[name])
                started = time.monotonic()
                await page.locator('#mu-sign-in').click()
                await page.locator('#mu-waiting-message').wait_for()
                auth_navigation = time.monotonic() - started
                assert 'Preparing your private workspace' in await page.locator('#mu-waiting-title').inner_text()
                assert not any('/api/settings' in url for url in requests)
                await page.screenshot(path=str(evidence / 'preparing-desktop.png'))
                await page.set_viewport_size({'width': 390, 'height': 844})
                await page.screenshot(path=str(evidence / 'preparing-mobile.png'))
                assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                await page.set_viewport_size({'width': 1280, 'height': 900})
                await lab.ready([name])
                await page.locator('#msg').wait_for(timeout=30000)
                await page.locator('#mu-account').wait_for(state='visible')
                assert name in await page.locator('#mu-account').inner_text()
                assert not await page.get_by_role('button', name='Accounts', exact=True).count()
                await page.locator('#msg').fill('Check my private workspace after automatic startup')
                await page.locator('#btnSend').click()
                await page.locator('#messages').get_by_text('Hello from your private Hermes runtime.', exact=True).wait_for(timeout=60000)
                for _ in range(100):
                    if await page.evaluate('!S.busy && S.session && !S.session.active_stream_id'):
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError('Chat did not finish after provisioning')
                # Use the real file panel and its native upload handler.
                if await page.locator('#btnWorkspacePanelEdgeToggle').is_visible():
                    await page.locator('#btnWorkspacePanelEdgeToggle').click()
                async with page.expect_file_chooser() as chooser:
                    await page.locator('#btnUploadWorkspace').click()
                async with page.expect_response(lambda response: '/api/workspace/upload' in response.url) as upload:
                    await (await chooser.value).set_files({'name': 'private-startup.txt',
                        'mimeType': 'text/plain', 'buffer': b'My private workspace is ready'})
                assert (await upload.value).status == 200
                await page.locator('#fileTree').get_by_text('private-startup.txt', exact=True).wait_for()
                await page.screenshot(path=str(evidence / 'ready-chat-and-workspace.png'))
                assert not errors, errors
                # Reproduce an existing account signing back in five seconds
                # after an admin edit: DB row is still ready, map is stale.
                uid = lab.users['alice']['id']
                old_runtime = lab.store.runtime(uid)
                status, _ = await lab.api('administrator', '/multiuser/api/users/' + uid, {'role':'user'})
                assert status == 200
                assert lab.store.runtime(uid)['state'] == 'ready'
                stale = json.loads((lab.settings.runtime_dir(uid) / 'profiles.json').read_text())
                assert stale['auth_version'] != lab.store.user(uid)['auth_version']
                context = await browser.new_context(viewport={'width':1280, 'height':900})
                recovery = await context.new_page()
                stale_requests = []
                recovery.on('request', lambda request: stale_requests.append(request.url))
                recovery.on('pageerror', lambda error: errors.append(str(error)))
                await recovery.goto(lab.origin + '/login')
                await recovery.locator('#mu-username').fill('alice')
                await recovery.locator('#mu-password').fill(lab.passwords['alice'])
                await recovery.locator('#mu-sign-in').click()
                await recovery.locator('#mu-waiting-message').wait_for()
                assert not any('/api/settings' in url for url in stale_requests)
                for width in (1280, 820, 390):
                    await recovery.set_viewport_size({'width':width, 'height':900})
                    await recovery.wait_for_function('() => document.documentElement.scrollWidth <= innerWidth')
                    await recovery.screenshot(path=str(evidence / f'stale-generation-preparing-{width}.png'))
                await recovery.set_viewport_size({'width':1280, 'height':900})
                await lab.ready(['alice'])
                await recovery.locator('#mu-account').wait_for()
                await recovery.wait_for_function("() => typeof S !== 'undefined' && S._bootReady && typeof _workspaceList !== 'undefined' && _workspaceList.length > 0")
                await recovery.locator('#mu-runtime-notice').wait_for(state='hidden')
                assert lab.store.runtime(uid)['generation'] != old_runtime['generation']
                for width in (1280, 820, 390):
                    await recovery.set_viewport_size({'width':width, 'height':900})
                    await recovery.wait_for_timeout(300)  # Native drawer resize transition.
                    close_menu = recovery.get_by_role('button', name='Close menu', exact=True)
                    if width <= 640 and await close_menu.is_visible():
                        await close_menu.click()
                        await recovery.wait_for_timeout(300)
                    await recovery.screenshot(path=str(evidence / f'stale-generation-ready-{width}.png'))
                    # The collapsed native file panel paints outside the
                    # desktop document. Record it, and check the visible
                    # composer separately from those offscreen controls.
                    layout = await recovery.evaluate("""() => ({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,
                      overflow:[...document.querySelectorAll('body *')].filter(n => n.getBoundingClientRect().right > innerWidth+1)
                        .slice(0,15).map(n => ({id:n.id,tag:n.tagName,cls:n.className,right:n.getBoundingClientRect().right}))})""")
                    (evidence / f'ready-layout-{width}.json').write_text(json.dumps(layout,indent=2))
                    await recovery.wait_for_function("() => {const r=document.getElementById('msg').getBoundingClientRect();return r.left>=0&&r.right<=innerWidth;}")
                await context.close()
                # A warm sign-in never provisions/restarts a prepared runtime.
                warm_before = lab.store.runtime(uid)
                interrupted = []
                for width in (1280, 820, 390):
                    context = await browser.new_context(viewport={'width':width, 'height':900})
                    retry = await context.new_page()
                    retry.on('pageerror', lambda error: errors.append(str(error)))
                    navigations = []
                    retry.on('framenavigated', lambda frame: navigations.append(frame.url) if frame == retry.main_frame else None)
                    failed = False
                    async def interrupt_once(route):
                        nonlocal failed
                        if not failed:
                            failed = True
                            await route.fulfill(status=503, content_type='application/json',
                                body=json.dumps({'error':'Assigned profiles are being updated', 'runtime_state':'starting'}))
                        else:
                            await route.continue_()
                    await retry.route('**/api/settings', interrupt_once)
                    await retry.goto(lab.origin + '/login')
                    await retry.locator('#mu-username').fill('alice')
                    await retry.locator('#mu-password').fill(lab.passwords['alice'])
                    started = time.monotonic()
                    await retry.locator('#mu-sign-in').click()
                    await retry.wait_for_function("() => typeof S !== 'undefined' && S._bootReady && typeof _workspaceList !== 'undefined' && _workspaceList.length > 0")
                    await retry.locator('#mu-runtime-notice').wait_for(state='hidden')
                    assert failed and len([url for url in navigations if url == lab.origin + '/']) == 2
                    # Same typed failure after boot must not discard a live
                    # draft/File or replay a write while reconnecting.
                    count = len(navigations)
                    await retry.locator('#msg').fill('Keep this unsent draft')
                    await retry.evaluate("() => { S.pendingFiles = [new File(['private'], 'draft.txt')]; }")
                    failed = False
                    await retry.evaluate("() => api('/api/settings').catch(() => {})")
                    await retry.wait_for_timeout(3500)
                    assert len(navigations) == count
                    assert await retry.locator('#msg').input_value() == 'Keep this unsent draft'
                    assert await retry.evaluate("() => S.pendingFiles[0] instanceof File")
                    await retry.evaluate('() => { S.pendingFiles = []; }')
                    await retry.locator('#msg').fill('')
                    await retry.wait_for_function("() => typeof S !== 'undefined' && S._bootReady && typeof _workspaceList !== 'undefined' && _workspaceList.length > 0")
                    await retry.locator('#mu-runtime-notice').wait_for(state='hidden')
                    assert len(navigations) == count + 1
                    interrupted.append({'width':width, 'seconds':round(time.monotonic() - started, 3),
                        'draft_and_file_preserved':True, 'automatic_reconnection':True})
                    await context.close()
                warm_after = lab.store.runtime(uid)
                assert warm_before['generation'] == warm_after['generation']
                assert warm_before['runtime_id'] == warm_after['runtime_id']
                assert not errors, errors
                (evidence / 'startup-browser.json').write_text(json.dumps({
                    'login_to_preparing_seconds': round(auth_navigation, 3),
                    'created_after_gateway_start': True, 'chat_auto_opens': True,
                    'real_agent_chat': True, 'workspace_upload_and_listing': True,
                    'role_is_user': True, 'manual_refresh_required': False,
                    'stale_generation_waits_then_auto_opens':True,
                    'warm_login_preserves_worker':True, 'interrupted_boot':interrupted,
                    'uncaught_errors': errors}, indent=2) + '\n')
            finally:
                await browser.close()
        lab.results['new_account_automatic_startup_chat_and_workspace'] = True
    finally:
        await lab.close()


if __name__ == '__main__':
    asyncio.run(run())
