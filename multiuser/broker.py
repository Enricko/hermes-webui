"""Per-account Unix-socket model broker and allowlisted public-network tunnels."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
import sqlite3
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

from multiuser.store import PolicyError

MODEL_ROUTES = {'/v1/chat/completions', '/v1/responses', '/v1/messages', '/v1/embeddings'}
MAX_MODEL_BODY = 16 * 1024 * 1024


def entitlement(store, uid):
    user = store.user(uid)
    if not user['enabled'] or not user['template_id']:
        raise PolicyError('Account is not enabled for model/network access')
    template = store.template(user['template_id'])['document']
    provider = store.provider(template['provider_id'])
    return user, template, provider


def model_payload(value, template, uid, route='/v1/chat/completions'):
    if not isinstance(value, dict) or value.get('model') not in template['models']:
        raise PolicyError('Model is not included in the assigned capability template')
    # No shared mutable provider state, files, vector stores, response history or
    # hosted code-interpreter containers can cross tenant boundaries.
    forbidden = {'previous_response_id', 'conversation', 'file_id', 'file_ids', 'vector_store_id',
                 'vector_store_ids', 'container', 'thread_id', 'assistant_id'}
    def references(node):
        if isinstance(node, dict):
            if node.get('type') == 'item_reference' or (isinstance(node.get('audio'), dict) and node['audio'].get('id')):
                raise PolicyError('Provider-side persistent resources are disabled')
            for field, item in node.items():
                if field in forbidden and item:
                    raise PolicyError('Provider-side persistent resources are disabled; use private local history')
                if field != 'tools':
                    references(item)
        elif isinstance(node, list):
            for item in node:
                references(item)
    references(value)
    tools = value.get('tools') or []
    if not isinstance(tools, list):
        raise PolicyError('Invalid local tool definitions')
    for tool in tools:
        allowed = ('function', 'custom', None) if route == '/v1/messages' else ('function', 'custom')
        if not isinstance(tool, dict) or tool.get('type') not in allowed:
            raise PolicyError('Only local function tools are available through shared providers')
    value = dict(value)
    if route in ('/v1/chat/completions', '/v1/responses'):
        value['store'] = False
    else:
        value.pop('store', None)
    if route in ('/v1/messages', '/v1/responses'):
        metadata = value.get('metadata') or {}
        if not isinstance(metadata, dict):
            raise PolicyError('Invalid provider metadata')
        metadata = dict(metadata)
        metadata['user_id' if route == '/v1/messages' else 'hermes_user_id'] = uid
        value['metadata'] = metadata
        value.pop('user', None)
    else:
        value['user'] = uid
    parameters = template['parameters']
    for key in ('temperature', 'top_p', 'max_tokens', 'service_tier'):
        if key in parameters and route != '/v1/embeddings':
            field = 'max_output_tokens' if key == 'max_tokens' and route == '/v1/responses' else key
            if key == 'max_tokens':
                value.setdefault(field, parameters[key])
            else:
                value[field] = parameters[key]
    maximum = parameters.get('max_tokens', template['agent'].get('max_tokens', 32768))
    for field in ('max_tokens', 'max_completion_tokens', 'max_output_tokens'):
        if field in value:
            amount = value[field]
            if isinstance(amount, bool) or not isinstance(amount, int) or not 1 <= amount <= maximum:
                raise PolicyError('Response token limit exceeds the assigned template')
    return value


def host_allowed(host, patterns):
    host = host.lower().rstrip('.')
    return any(pattern == '*' or host == pattern or
               (pattern.startswith('*.') and host.endswith(pattern[1:]) and host != pattern[2:])
               for pattern in patterns)


async def public_addresses(host, port, patterns):
    if not host or port not in (80, 443) or not host_allowed(host, patterns):
        raise PolicyError('Network destination is not allowed by the account template')
    try:
        answers = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PolicyError('Network destination could not be resolved') from exc
    addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise PolicyError('Private, local, reserved and metadata addresses are never egress destinations')
    # The caller connects to these numeric addresses, never resolves again.
    return addresses


class Brokers:
    def __init__(self, settings):
        self.settings = settings
        self.store = settings.store()
        self.sites = {}
        self.limits = {}
        self.client = None
        self.task = None
        self.retrying = set()

    async def start(self):
        self.client = aiohttp.ClientSession(trust_env=False, auto_decompress=False,
            timeout=aiohttp.ClientTimeout(total=None, connect=15, sock_read=180))
        self.task = asyncio.create_task(self.watch())

    async def close(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
        for runner, egress in self.sites.values():
            await runner.cleanup()
            egress.close()
            await egress.wait_closed()
        if self.client:
            await self.client.close()

    async def watch(self):
        while True:
            try:
                users = self.store.users()
            except sqlite3.Error:
                # A temporary control-db lock must not permanently stop account
                # discovery. Existing sockets keep their own account authority.
                await asyncio.sleep(0.5)
                continue
            for user in users:
                uid = user['id']
                try:
                    directory = self.settings.runtime_dir(uid) / 'broker'
                    if uid in self.sites or not directory.is_dir():
                        continue
                    if directory.is_symlink() or directory.stat().st_uid != self.settings.gateway_uid:
                        continue
                    await self.bind(uid)
                    self.retrying.discard(uid)
                except (OSError, PolicyError) as exc:
                    # The trusted provisioner creates/chowns directories in
                    # separate steps. A newly published account can briefly
                    # encounter EACCES/ENOENT; retry only that account instead of
                    # losing the watcher for every future account.
                    if uid not in self.retrying:
                        logging.warning('Private account broker not ready (%s); retrying', type(exc).__name__)
                    self.retrying.add(uid)
            await asyncio.sleep(0.5)

    async def bind(self, uid):
        path = self.settings.broker_socket(uid)
        egress_path = path.with_name('egress.sock')
        for target in (path, egress_path):
            if target.exists() or target.is_symlink():
                target.unlink()
        app = web.Application(client_max_size=MAX_MODEL_BODY)
        async def model(request):
            return await self.model(uid, request)
        app.router.add_route('*', '/{path:.*}', model)
        runner = web.AppRunner(app, access_log=None)
        server = None
        created = []
        try:
            await runner.setup()
            site = web.UnixSite(runner, str(path))
            await site.start()
            created.append(path)
            path.chmod(0o660)
            async def tunnel(reader, writer):
                await self.egress(uid, reader, writer)
            server = await asyncio.start_unix_server(tunnel, str(egress_path), limit=16384)
            created.append(egress_path)
            egress_path.chmod(0o660)
        except BaseException:
            if server:
                server.close()
                await server.wait_closed()
            await runner.cleanup()
            for target in created:
                target.unlink(missing_ok=True)
            raise
        self.sites[uid] = (runner, server)
        self.limits[uid] = asyncio.Semaphore(4)

    async def model(self, uid, request):
        response = None
        try:
            _user, template, provider = entitlement(self.store, uid)
            if request.method == 'GET' and request.path == '/v1/models':
                return web.json_response({'object': 'list', 'data': [
                    {'id': model, 'object': 'model', 'owned_by': 'assigned-template'} for model in template['models']]})
            if request.method != 'POST' or request.path not in MODEL_ROUTES or request.query_string:
                raise PolicyError('Provider route is not available')
            value = model_payload(await request.json(), template, uid, request.path)
            suffix = request.path[len('/v1'):]
            endpoint = provider['base_url'] + suffix
            # No browser/worker cookies, authorization or identity headers pass.
            headers = {'Content-Type': 'application/json', 'Accept-Encoding': 'identity',
                       'Authorization': 'Bearer ' + provider['secret']}
            if request.path == '/v1/messages':
                headers.update({'x-api-key': provider['secret'], 'anthropic-version': '2023-06-01'})
            async with self.limits[uid]:
                async with self.client.post(endpoint, json=value, headers=headers, allow_redirects=False) as upstream:
                    if upstream.status >= 300:
                        # Provider error text can echo a rejected key. Never expose it.
                        return web.json_response({'error': {'message': 'The configured provider rejected this request',
                            'type': 'provider_error', 'code': upstream.status}}, status=502)
                    response = web.StreamResponse(status=upstream.status,
                        headers={key: upstream.headers[key] for key in ('Content-Type', 'Content-Encoding') if key in upstream.headers})
                    await response.prepare(request)
                    pending = asyncio.create_task(upstream.content.readany())
                    try:
                        while True:
                            done, _ = await asyncio.wait({pending}, timeout=0.5)
                            entitlement(self.store, uid)
                            if not done:
                                continue
                            data = pending.result()
                            if not data:
                                break
                            await response.write(data)
                            pending = asyncio.create_task(upstream.content.readany())
                    finally:
                        pending.cancel()
                    await response.write_eof()
                    return response
        except (PolicyError, ValueError, TypeError, web.HTTPException):
            if response is not None and response.prepared:
                with contextlib.suppress(ConnectionError):
                    await response.write_eof()
                return response
            return web.json_response({'error': {'message': 'Model request refused by account policy'}}, status=403)
        except (aiohttp.ClientError, OSError, TimeoutError):
            if response is not None and response.prepared:
                with contextlib.suppress(ConnectionError):
                    await response.write_eof()
                return response
            return web.json_response({'error': {'message': 'Model provider unavailable'}}, status=502)

    async def egress(self, uid, reader, writer):
        remote_writer = None
        try:
            _user, template, _provider = entitlement(self.store, uid)
            first = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout=10)
            if len(first) > 8192:
                raise PolicyError('Proxy headers are too large')
            lines = first.decode('iso-8859-1').split('\r\n')
            method, target, version = lines[0].split(' ')
            if version not in ('HTTP/1.0', 'HTTP/1.1'):
                raise PolicyError('Unsupported proxy framing')
            if method == 'CONNECT':
                parsed = urlsplit('//' + target)
                host, port = parsed.hostname, parsed.port or 443
                if parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
                    raise PolicyError('Invalid CONNECT destination')
            else:
                parsed = urlsplit(target)
                if parsed.scheme != 'http' or parsed.username or parsed.password or parsed.fragment:
                    raise PolicyError('Use HTTPS CONNECT or an absolute HTTP URL')
                host, port = parsed.hostname, parsed.port or 80
                if method not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
                    raise PolicyError('Unsupported proxy method')
            addresses = await public_addresses(host, port, template['egress_hosts'])
            # A pinned numeric connect prevents DNS rebinding to host/other tenants.
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(addresses[0], port), timeout=15)
            if method == 'CONNECT':
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await writer.drain()
            else:
                # Drop proxy credentials and all caller Host overrides. Close the
                # connection after this request so a second target cannot be smuggled.
                headers = []
                seen = set()
                for line in lines[1:]:
                    if not line:
                        continue
                    name, value = line.split(':', 1)
                    name = name.lower()
                    if name in seen or name == 'transfer-encoding':
                        raise PolicyError('Ambiguous proxy framing')
                    seen.add(name)
                    if name not in ('host', 'proxy-authorization', 'proxy-connection', 'connection'):
                        headers.append(name + ':' + value)
                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query
                authority = host + (':' + str(port) if port != 80 else '')
                head = f'{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n'
                remote_writer.write((head + '\r\n'.join(headers) + '\r\n\r\n').encode('iso-8859-1'))
                await remote_writer.drain()
            async def copy(source, destination):
                while chunk := await source.read(65536):
                    entitlement(self.store, uid)
                    destination.write(chunk)
                    await destination.drain()
            async def request_body():
                if method == 'CONNECT':
                    await copy(reader, remote_writer)
                    return
                length = next((line.split(':', 1)[1].strip() for line in lines[1:]
                               if line.lower().startswith('content-length:')), '0')
                if not length.isascii() or not length.isdigit() or int(length) > 32 * 1024 * 1024:
                    raise PolicyError('Invalid HTTP proxy body length')
                remaining = int(length)
                while remaining:
                    part = await reader.readexactly(min(65536, remaining))
                    entitlement(self.store, uid)
                    remote_writer.write(part)
                    await remote_writer.drain()
                    remaining -= len(part)
                # A following request is never forwarded to the approved server.
                await asyncio.Future()
            left = asyncio.create_task(request_body())
            right = asyncio.create_task(copy(remote_reader, writer))
            try:
                await asyncio.wait({left, right}, return_when=asyncio.FIRST_COMPLETED, timeout=300)
            finally:
                left.cancel()
                right.cancel()
        except (PolicyError, ValueError, OSError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            with contextlib.suppress(OSError):
                writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                await writer.drain()
        finally:
            if remote_writer:
                remote_writer.close()
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
