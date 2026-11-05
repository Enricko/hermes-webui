"""Opt-in real-browser/account API integration with synthetic-only state.

HERMES_WEBUI_BROWSER_TESTS=1 ./scripts/test.sh -q tests/test_member_browser.py
Install Playwright plus Chromium in the development environment first.
"""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time

import pytest

from api.access_policy import PolicyStore
from api.provider_broker import CredentialVault
from api.user_roles import hash_password
from tests.test_member_chat import provider  # noqa: F401 -- shared synthetic HTTP provider fixture

pytestmark = pytest.mark.skipif(os.getenv('HERMES_WEBUI_BROWSER_TESTS') != '1', reason='opt-in browser evidence')


@pytest.fixture
def deployment(tmp_path, provider):  # noqa: F811 -- imported pytest fixture dependency
    users = tmp_path / 'users.json'
    password = 'synthetic-browser-password'
    password_hash = hash_password(password)
    users.write_text(json.dumps({'users': {
        name: {'id': name+'-id', 'role': 'admin' if name=='admin' else 'user', 'password': password_hash,
               'profile': name, 'workspaces': [str(tmp_path / name)]}
        for name in ('admin', 'alice', 'bob')
    }}))
    policy = PolicyStore.initialize(tmp_path / 'policy.sqlite', 'admin-id')
    for name in ('alice', 'bob'):
        policy.put_account('admin-id', name+'-id')
    binding = {'protocol':'openai', 'base_url':provider[0], 'account_id':'synthetic-account'}
    for kind, identifier, metadata in [('profile','writer',{'system_prompt':'Write clearly.'}),
                                      ('workspace','private',{}),('skill','coding',{'content':'Coding skill'}),
                                      ('connection','managed',binding)]:
        policy.put_resource('admin-id',identifier,kind=kind,label=identifier,binding=metadata)
    for name in ('admin','alice','bob'):
        policy.replace_grants('admin-id', name+'-id', {'writer':[],'private':[],'coding':[],'managed':['allowed-model']})
    CredentialVault(tmp_path/'member-data'/'credentials.json').put('managed','synthetic-browser-provider-key',binding)
    repo = Path(__file__).resolve().parents[1]
    environment = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HERMES_HOME':str(tmp_path/'agent-home'),
                   'HERMES_WEBUI_STATE_DIR':str(tmp_path/'webui'), 'HERMES_WEBUI_USERS_FILE':str(users),
                   'HERMES_WEBUI_ACCESS_POLICY_FILE':str(policy.path),'HERMES_WEBUI_MEMBER_CHAT':'1',
                   'HERMES_WEBUI_SKIP_ONBOARDING':'1','PYTHONUNBUFFERED':'1'}
    log = tmp_path/'server.log'
    with log.open('w') as output:
        process = subprocess.Popen([sys.executable,str(repo/'scripts'/'serve_members.py'),'--port','0'],
                                   cwd=repo,env=environment,stdout=output,stderr=output)
        try:
            deadline = time.monotonic()+20
            match = None
            while process.poll() is None and time.monotonic()<deadline:
                match = re.search(r'Private chat listening on (http://127\.0\.0\.1:\d+)', log.read_text())
                if match:
                    break
                time.sleep(.05)
            assert match, 'isolated test server did not start'
            yield match.group(1), password, tmp_path, policy
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


@pytest.fixture
def browser():
    playwright = pytest.importorskip('playwright.sync_api')
    with playwright.sync_playwright() as manager:
        chromium = manager.chromium.launch(headless=True)
        yield chromium
        chromium.close()


def sign_in(page, base, username, password, destination):
    page.goto(base+'/login?next='+destination)
    page.locator('#user').fill(username)
    page.locator('#pw').fill(password)
    page.locator('#login-form button[type=submit], #form button[type=submit], form button[type=submit]').first.click()
    page.wait_for_url(base+destination)


def shot(page, name, tmp_path):
    root = Path(os.getenv('HERMES_WEBUI_BROWSER_SHOTS',str(tmp_path/'screenshots')))
    root.mkdir(parents=True,exist_ok=True)
    page.screenshot(path=str(root/(name+'.png')),full_page=True)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')


def test_admin_account_and_access_ui(browser, deployment):
    base,password,tmp_path,_ = deployment
    context = browser.new_context(viewport={'width':1440,'height':1000})
    page = context.new_page()
    sign_in(page,base,'admin',password,'/admin/users')
    page.get_by_role('button',name='New account',exact=True).wait_for()
    page.get_by_text('Accounts and access loaded.',exact=True).wait_for()
    assert page.request.post(base+'/api/terminal/start',data={}).status==404
    shot(page,'admin-desktop-before',tmp_path)
    # Missing CSRF proof cannot create a username/password account.
    denied = page.request.post(base+'/api/admin/users',headers={'Origin':base},data={
        'action':'create','username':'forbidden','password':'synthetic-password','role':'admin'})
    assert denied.status==403
    page.locator('#resource-id').fill('reading')
    page.locator('#resource-kind').select_option('skill')
    page.locator('#resource-label').fill('Reading skill')
    page.locator('#resource-content').fill('Read carefully and cite provided text.')
    page.get_by_role('button',name='Save resource',exact=True).click()
    page.get_by_text('Resource saved.',exact=True).wait_for()
    page.locator('#username').fill('charlie')
    page.locator('#password').fill('synthetic-charlie-password')
    page.get_by_role('button',name='Create account',exact=True).click()
    page.get_by_text('Account saved.',exact=True).wait_for()
    for checkbox in page.locator('#grants input[type=checkbox]').all():
        checkbox.check()
    page.locator('#grants textarea').fill('allowed-model')
    page.get_by_role('button',name='Save access',exact=True).click()
    page.get_by_text('Access saved.',exact=True).wait_for()
    assert page.locator('#password').input_value()==''
    shot(page,'admin-desktop-after',tmp_path)
    for width in (768,390):
        page.set_viewport_size({'width':width,'height':900})
        shot(page,f'admin-{width}',tmp_path)
    other = browser.new_context()
    member = other.new_page()
    sign_in(member,base,'charlie','synthetic-charlie-password','/member')
    member.get_by_text('Your workspace is ready.',exact=True).wait_for()
    page.locator('#enabled').uncheck()
    page.get_by_role('button',name='Save account',exact=True).click()
    page.get_by_text('Account saved.',exact=True).wait_for()
    assert member.request.get(base+'/api/member/catalog').status==401
    other.close()
    context.close()


def test_member_chat_files_and_other_user_denials(browser, deployment):
    base,password,tmp_path,_ = deployment
    context = browser.new_context(viewport={'width':1440,'height':1000})
    page = context.new_page()
    sign_in(page,base,'alice',password,'/member')
    page.get_by_text('Your workspace is ready.',exact=True).wait_for()
    page.locator('#message').fill('Private message from Alice')
    page.get_by_role('button',name='Send',exact=True).click()
    page.get_by_text('Response received.',exact=True).wait_for()
    assert page.locator('#messages').inner_text().count('synthetic reply')==1
    conversation = page.request.get(base+'/api/member/conversations').json()['conversations'][0]
    csrf = page.locator('meta[name=csrf-token]').get_attribute('content')
    headers = {'X-Hermes-CSRF-Token':csrf,'Origin':base}
    selection = conversation['context']
    result = page.request.post(base+'/api/member/files',headers=headers,data={
        'action':'write','context':selection,'path':'alice.txt','content':'YWxpY2UtcHJpdmF0ZQ=='})
    assert result.ok
    page.get_by_role('button',name='Refresh files',exact=True).click()
    page.get_by_role('button',name='alice.txt',exact=True).wait_for()
    shot(page,'member-desktop',tmp_path)
    page.set_viewport_size({'width':390,'height':844})
    shot(page,'member-mobile',tmp_path)
    response = page.request.get(base+'/api/admin/users')
    assert response.status==403
    response = page.request.post(base+'/api/chat/start',headers=headers,data={'session_id':'foreign','message':'forbidden'})
    assert response.status==404
    # Browser account switch: private transcript/file state is removed, and
    # the new account cannot read another owner's durable conversation/file.
    page.get_by_role('button',name='Sign out',exact=True).click()
    page.wait_for_url(base+'/login')
    sign_in(page,base,'bob',password,'/member')
    page.get_by_text('Your workspace is ready.',exact=True).wait_for()
    assert 'Private message from Alice' not in page.locator('body').inner_text()
    assert page.request.get(base+'/api/member/conversation?id='+conversation['id']).status==403
    csrf = page.locator('meta[name=csrf-token]').get_attribute('content')
    assert page.request.post(base+'/api/member/files',headers={'X-Hermes-CSRF-Token':csrf,'Origin':base},data={
        'action':'read','context':selection,'path':'alice.txt'}).status==400
    assert page.request.post(base+'/api/admin/users',headers={'X-Hermes-CSRF-Token':csrf,'Origin':base},data={
        'action':'update','username':'bob','role':'admin'}).status==403
    context.close()
