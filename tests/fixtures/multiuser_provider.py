"""Deterministic external model fixture; workers, Agent tools and Docker are real."""

import asyncio
import json
import time
import uuid

from aiohttp import web


class ModelFixture:
    def __init__(self, expected_secret):
        self.expected_secret = expected_secret
        self.requests = []
        self.waiting = {}
        self.release = {}

    async def completion(self, request):
        payload = await request.json()
        assert request.headers.get('Authorization') == 'Bearer ' + self.expected_secret
        assert self.expected_secret not in json.dumps(payload)
        uid = payload.get('user')
        self.requests.append({'user_id': uid, 'model': payload.get('model'),
                              'tools': [t.get('function', {}).get('name') for t in payload.get('tools', [])],
                              'store': payload.get('store')})
        messages = payload.get('messages', [])
        last_user = max((i for i, message in enumerate(messages) if message.get('role') == 'user'), default=-1)
        text = str(messages[last_user].get('content', '')) if last_user >= 0 else ''
        has_result = any(message.get('role') == 'tool' for message in messages[last_user + 1:])
        tool = None
        if 'CONVERT_SHARED' in text and not has_result:
            tool = {'id': 'call_' + uuid.uuid4().hex[:12], 'type': 'function', 'function': {
                'name': 'terminal', 'arguments': json.dumps({'command':
                    'python /shared/tools/png_to_jpg.py --input /workspace/same.png --output /workspace/same.jpg --tmp-dir /tmp'})}}
        content = 'Shared converter finished.' if has_result else 'Hello from your private Hermes runtime.'
        identifier = 'chatcmpl-' + uuid.uuid4().hex
        if not payload.get('stream'):
            message = {'role': 'assistant', 'content': None if tool else content}
            if tool:
                message['tool_calls'] = [tool]
            return web.json_response({'id': identifier, 'object': 'chat.completion', 'created': int(time.time()),
                'model': payload['model'], 'choices': [{'index': 0, 'message': message,
                'finish_reason': 'tool_calls' if tool else 'stop'}],
                'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15}})
        response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await response.prepare(request)
        async def event(delta, finish=None):
            data = {'id': identifier, 'object': 'chat.completion.chunk', 'created': int(time.time()),
                    'model': payload['model'], 'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}
            await response.write(('data: ' + json.dumps(data) + '\n\n').encode())
        try:
            await event({'role': 'assistant'})
            if 'BLOCK_FOR_CANCEL' in text:
                self.waiting.setdefault(uid, asyncio.Event()).set()
                release = self.release.setdefault(uid, asyncio.Event())
                while not release.is_set():
                    await event({'content': 'waiting '})
                    await asyncio.sleep(0.2)
            if tool:
                await event({'tool_calls': [{'index': 0, **tool}]})
                await event({}, 'tool_calls')
            else:
                await event({'content': content})
                await event({}, 'stop')
            await response.write(b'data: [DONE]\n\n')
        except ConnectionError:
            pass
        return response

    def app(self):
        app = web.Application()
        async def models(request):
            assert request.headers.get('Authorization') == 'Bearer ' + self.expected_secret
            return web.json_response({'data': [{'id': 'fixture-model'}, {'id': 'fixture-extra'}]})
        app.router.add_get('/v1/models', models)
        app.router.add_post('/v1/chat/completions', self.completion)
        return app
