#!/usr/bin/env python3
"""A user created after gateway startup opens chat/files without a manual refresh.

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
                (evidence / 'startup-browser.json').write_text(json.dumps({
                    'login_to_preparing_seconds': round(auth_navigation, 3),
                    'created_after_gateway_start': True, 'chat_auto_opens': True,
                    'real_agent_chat': True, 'workspace_upload_and_listing': True,
                    'role_is_user': True, 'manual_refresh_required': False, 'uncaught_errors': errors}, indent=2) + '\n')
            finally:
                await browser.close()
        lab.results['new_account_automatic_startup_chat_and_workspace'] = True
    finally:
        await lab.close()


if __name__ == '__main__':
    asyncio.run(run())
