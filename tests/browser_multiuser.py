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
                assert not failures, failures
                assert not statuses, statuses
            finally:
                await browser.close()
        lab.results['browser_desktop_narrow_mobile_login_admin_logout'] = True
        (evidence / 'browser-acceptance.json').write_text(json.dumps({'viewports': [1440, 760, 390],
            'uncaught_errors': failures, 'http_errors': statuses, 'result': 'pass',
            'before_reference': 'same upstream chrome with only the additive account bar visually hidden'}, indent=2) + '\n')
    finally:
        await lab.close()


if __name__ == '__main__':
    asyncio.run(run())
