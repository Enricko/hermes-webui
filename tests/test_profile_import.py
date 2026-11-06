from dataclasses import replace

import pytest

from api.access_policy import AccessContext, AccessDenied, PolicyStore


def test_real_profile_import_has_persistent_ids_no_implicit_grants(tmp_path):
    store=PolicyStore.initialize(tmp_path/'policy.sqlite','admin')
    imported=store.import_profiles('admin',['default','stayfalz'])
    assert [p['name'] for p in imported]==['default','stayfalz']
    assert imported==store.import_profiles('admin',['stayfalz','default'])
    snapshot=store.snapshot('admin')
    assert snapshot['grants']==[]
    assert all('api_key' not in row['binding'] and 'password' not in row['binding'] for row in snapshot['resources'])
    store.put_account('admin','alice')
    store.put_resource('admin','workspace',kind='workspace',label='private',binding={})
    store.put_resource('admin','connection',kind='connection',label='managed',binding={})
    profile=next(p['id'] for p in imported if p['name']=='stayfalz')
    store.replace_grants('admin','alice',{profile:[],'workspace':[],'connection':['model']})
    context=AccessContext('alice',profile,'workspace','connection','model')
    admission=store.authorize(context)
    store.import_profiles('admin',['default'])
    with pytest.raises(AccessDenied):store.authorize(context)
    with pytest.raises(AccessDenied):store.revalidate(admission)
    with pytest.raises(AccessDenied):store.replace_grants('admin','alice',{profile:[]})
    restored=store.import_profiles('admin',['default','stayfalz'])
    assert next(p['id'] for p in restored if p['name']=='stayfalz')==profile
    assert store.authorize(context).profile_instance_id==admission.profile_instance_id


def test_non_admin_cannot_import_profiles(tmp_path):
    store=PolicyStore.initialize(tmp_path/'policy.sqlite','admin')
    store.put_account('admin','alice')
    with pytest.raises(AccessDenied):store.import_profiles('alice',['default'])


def test_tool_grants_are_explicit(tmp_path):
    store=PolicyStore.initialize(tmp_path/'policy.sqlite','admin')
    store.put_account('admin','alice')
    for name,kind in [('profile','profile'),('workspace','workspace'),('connection','connection'),('git','tool')]:
        store.put_resource('admin',name,kind=kind,label=name,binding={})
    grants={'profile':[],'workspace':[],'connection':['model']}
    store.replace_grants('admin','alice',grants)
    context=AccessContext('alice','profile','workspace','connection','model',tools=('git',))
    with pytest.raises(AccessDenied):store.authorize(context)
    store.replace_grants('admin','alice',{**grants,'git':[]})
    assert store.authorize(context)
    with pytest.raises(AccessDenied):store.authorize(replace(context,tools=('other',)))


def test_own_username_workspace_is_automatic_not_a_selectable_host_path(tmp_path):
    store=PolicyStore.initialize(tmp_path/'policy.sqlite','admin')
    store.put_resource('admin','own',kind='workspace',label='Private workspace',binding={'scope':'login-username'})
    store.put_resource('admin','other',kind='workspace',label='Other workspace',binding={})
    store.put_account('admin','alice')
    grants=store.snapshot('admin')['grants']
    assert {(r['account_id'],r['resource_id']) for r in grants}=={('alice','own')}
    store.replace_grants('admin','alice',{})
    assert [r['resource_id'] for r in store.snapshot('admin')['grants'] if r['account_id']=='alice']==['own']
