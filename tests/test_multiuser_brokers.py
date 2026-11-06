"""New accounts survive provisioning races without losing the broker watcher."""

import asyncio
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile

import pytest
import pytest_asyncio

from multiuser.broker import Brokers
from multiuser.settings import Settings


@pytest_asyncio.fixture
async def brokers():
    root = Path(tempfile.mkdtemp(prefix='hmu-broker-', dir='/tmp'))
    settings = Settings(root=root, gateway_uid=os.getuid())
    settings.store().initialize()
    service = Brokers(settings)
    try:
        yield settings, service
    finally:
        # Also clean up the pre-fix failed-task case, keeping the original
        # assertion as evidence instead of leaking its HTTP client/runners.
        if service.task and service.task.done():
            service.task.exception()
            service.task = None
        await service.close()
        shutil.rmtree(root)


@pytest.mark.asyncio
async def test_new_account_permission_and_bind_races_do_not_kill_other_brokers(brokers, monkeypatch):
    settings, service = brokers
    store = settings.store()
    password = secrets.token_urlsafe(24)
    first = store.create_user('administrator', password, role='admin', bootstrap=True)
    (settings.runtime_dir(first['id']) / 'broker').mkdir(parents=True)
    await service.start()
    for _ in range(30):
        if first['id'] in service.sites:
            break
        await asyncio.sleep(0.05)
    assert first['id'] in service.sites
    original_socket_inode = settings.broker_socket(first['id']).stat().st_ino
    second = store.create_user('alice', password)
    directory = settings.runtime_dir(second['id']) / 'broker'
    directory.mkdir(parents=True)
    real_is_dir, real_bind = Path.is_dir, service.bind
    failures = {'permission': 0, 'bind': 0}

    def preparing_directory(path):
        if path == directory and not failures['permission']:
            failures['permission'] += 1
            raise PermissionError('Parent is still being provisioned')
        return real_is_dir(path)

    async def temporarily_unavailable(uid):
        if uid == second['id'] and not failures['bind']:
            failures['bind'] += 1
            raise OSError('Socket directory is not ready')
        await real_bind(uid)

    monkeypatch.setattr(Path, 'is_dir', preparing_directory)
    monkeypatch.setattr(service, 'bind', temporarily_unavailable)
    for _ in range(80):
        if second['id'] in service.sites or service.task.done():
            break
        await asyncio.sleep(0.05)
    assert not service.task.done(), 'A transient provisioning error killed account discovery'
    assert failures == {'permission': 1, 'bind': 1}
    assert second['id'] in service.sites
    assert settings.broker_socket(second['id']).is_socket()
    assert settings.broker_socket(first['id']).stat().st_ino == original_socket_inode


@pytest.mark.asyncio
async def test_partial_bind_closes_and_removes_its_socket_before_retry(brokers, monkeypatch):
    settings, service = brokers
    user = settings.store().create_user('administrator', secrets.token_urlsafe(24), role='admin', bootstrap=True)
    (settings.runtime_dir(user['id']) / 'broker').mkdir(parents=True)
    real_server = asyncio.start_unix_server

    async def unavailable(*_args, **_kwargs):
        raise OSError('Egress listener cannot bind yet')

    monkeypatch.setattr(asyncio, 'start_unix_server', unavailable)
    with pytest.raises(OSError):
        await service.bind(user['id'])
    assert not settings.broker_socket(user['id']).exists()
    assert user['id'] not in service.sites
    monkeypatch.setattr(asyncio, 'start_unix_server', real_server)
    await service.bind(user['id'])
    assert settings.broker_socket(user['id']).is_socket()


@pytest.mark.asyncio
async def test_transient_control_database_open_failure_retries_account_discovery(brokers, monkeypatch):
    settings, service = brokers
    user = settings.store().create_user('administrator', secrets.token_urlsafe(24), role='admin', bootstrap=True)
    (settings.runtime_dir(user['id']) / 'broker').mkdir(parents=True)
    real_users = service.store.users
    calls = []

    def temporarily_unavailable_database():
        calls.append(True)
        if len(calls) == 1:
            raise sqlite3.OperationalError('unable to open database file')
        return real_users()

    monkeypatch.setattr(service.store, 'users', temporarily_unavailable_database)
    await service.start()
    for _ in range(60):
        if user['id'] in service.sites or service.task.done():
            break
        await asyncio.sleep(0.05)
    assert not service.task.done()
    assert len(calls) >= 2
    assert settings.broker_socket(user['id']).is_socket()
