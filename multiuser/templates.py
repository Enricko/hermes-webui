"""Explicit, non-secret capability templates. Personal state is never a template."""

from __future__ import annotations

import copy
from pathlib import PurePosixPath
import re

from multiuser.store import PolicyError, identifier

FIELDS = {"provider_id", "model", "models", "parameters", "agent", "soul", "skills", "tools", "egress_hosts", "skill_bundle_id", "model_catalog", "connections"}
PARAMETERS = {"temperature", "top_p", "max_tokens", "reasoning_effort", "service_tier", "context_length"}
AGENT_FIELDS = {"max_iterations", "max_turns", "max_tokens", "reasoning_effort", "system_message"}
SECRET_WORDS = re.compile(r"(?:password|secret|token|credential|api_key|auth\.json|user\.md)", re.I)


def relative_file(value):
    if not isinstance(value, str) or '\\' in value or '\x00' in value:
        raise PolicyError("Invalid template file path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(p in ('', '.', '..') for p in path.parts):
        raise PolicyError("Template paths must be relative and cannot traverse directories")
    if any(p.startswith('.') for p in path.parts) or SECRET_WORDS.search(value):
        raise PolicyError("Personal/credential files cannot be template files")
    if len(value) > 180:
        raise PolicyError("Template path is too long")
    return str(path)


def validate_template(value):
    if not isinstance(value, dict) or set(value) - FIELDS:
        raise PolicyError("Template contains unsupported fields")
    out = copy.deepcopy(value)
    identifier(out.get('provider_id'))
    if out.get('skill_bundle_id') is not None:
        identifier(out['skill_bundle_id'])
    if out.setdefault('model_catalog', 'allowlist') not in ('allowlist', 'provider'):
        raise PolicyError('Model catalog must be allowlist or provider')
    connections = out.setdefault('connections', [])
    if not isinstance(connections, list) or len(connections) > 16:
        raise PolicyError('Select at most 16 named provider connections')
    seen_ids, seen_names = set(), set()
    for connection in connections:
        if not isinstance(connection, dict) or set(connection) != {'provider_id', 'name', 'model'}:
            raise PolicyError('Connections contain only an assigned provider ID, name and default model')
        pid = identifier(connection['provider_id'])
        name, model = connection['name'], connection['model']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}', name):
            raise PolicyError('Invalid provider display name')
        slug = re.sub(r'[^a-z0-9._-]+', '-', name.lower()).strip('-')
        if slug == 'account-primary':
            raise PolicyError('The account primary provider name is reserved')
        if not isinstance(model, str) or not 1 <= len(model) <= 200 or any(ord(c) < 32 for c in model):
            raise PolicyError('Select a default model for each connection')
        if pid in seen_ids or slug in seen_names:
            raise PolicyError('Duplicate provider connection or name')
        seen_ids.add(pid); seen_names.add(slug)
    models = out.get('models', [out.get('model')])
    if not isinstance(models, list) or not 1 <= len(models) <= 64 or any(not isinstance(m, str) or not 1 <= len(m) <= 200 for m in models):
        raise PolicyError("Select 1–64 explicit models")
    out['models'] = list(dict.fromkeys(models))
    if out.get('model') not in out['models']:
        raise PolicyError("Default model must be in the model allowlist")
    for key, allowed in [('parameters', PARAMETERS), ('agent', AGENT_FIELDS)]:
        settings = out.setdefault(key, {})
        if not isinstance(settings, dict) or set(settings) - allowed:
            raise PolicyError(f"Unsupported {key} fields")
        for name, setting in settings.items():
            if name in ('temperature', 'top_p'):
                maximum = 2 if name == 'temperature' else 1
                if isinstance(setting, bool) or not isinstance(setting, (int, float)) or not 0 <= setting <= maximum:
                    raise PolicyError(f"Invalid {name}")
            elif name in ('max_tokens', 'context_length', 'max_iterations', 'max_turns'):
                maximum = 256 if name in ('max_iterations', 'max_turns') else 1048576
                if isinstance(setting, bool) or not isinstance(setting, int) or not 1 <= setting <= maximum:
                    raise PolicyError(f"Invalid {name}")
                if name == 'context_length' and setting < 64000:
                    raise PolicyError('The pinned Hermes Agent requires at least 64,000 context tokens')
            elif name == 'reasoning_effort' and setting not in ('none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'):
                raise PolicyError("Invalid reasoning effort")
            elif name == 'service_tier' and setting not in ('auto', 'default', 'flex', 'priority'):
                raise PolicyError("Invalid service tier")
            elif name == 'system_message' and (not isinstance(setting, str) or len(setting) > 16384):
                raise PolicyError("System instructions are too long")
    if ('max_iterations' in out['agent'] and 'max_turns' in out['agent'] and
            out['agent']['max_iterations'] != out['agent']['max_turns']):
        raise PolicyError('Specify one consistent Agent turn budget')
    soul = out.setdefault('soul', '')
    if not isinstance(soul, str) or len(soul.encode()) > 65536:
        raise PolicyError("SOUL must be at most 64 KiB")
    skills = out.setdefault('skills', {})
    if not isinstance(skills, dict) or len(skills) > 128:
        raise PolicyError("Select at most 128 skill files")
    clean = {}
    for name, content in skills.items():
        name = relative_file(name)
        if not isinstance(content, str) or len(content.encode()) > 262144:
            raise PolicyError("Skill file must be text of at most 256 KiB")
        clean[name] = content
    out['skills'] = clean
    tools = out.setdefault('tools', [])
    if not isinstance(tools, list) or len(tools) > 64:
        raise PolicyError("Select at most 64 tools")
    for tool in tools:
        identifier(tool)
    if len(set(tools)) != len(tools):
        raise PolicyError("Duplicate tools are not allowed")
    hosts = out.setdefault('egress_hosts', [])
    if not isinstance(hosts, list) or len(hosts) > 128:
        raise PolicyError("Invalid network allowlist")
    for host in hosts:
        if not isinstance(host, str) or host != host.lower() or not (host == '*' or re.fullmatch(r'(?:\*\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host)):
            raise PolicyError("Network entries must be lowercase DNS names, *.domain or explicit * for public internet")
    return out


def worker_config(template, *, profile_id=None, skills_path='/shared/skills'):
    """Shared secrets and legacy personal/integration state cannot enter this output."""
    document = validate_template(template)
    lane = ('http://127.0.0.1:8000/profiles/' + identifier(profile_id) if profile_id else 'http://127.0.0.1:8000')
    model = {'provider': 'custom', 'default': document['model'],
             'base_url': lane + '/providers/' + document['provider_id'] + '/v1' if profile_id else lane + '/v1',
             'api_key': 'tenant-broker', 'api_mode': 'chat_completions'}
    parameters = document['parameters']
    if 'context_length' in parameters:
        model['context_length'] = parameters['context_length']
    agent = dict(document['agent'])
    # Upstream WebUI reads agent.max_turns and passes it as the AIAgent
    # constructor's max_iterations; these are different configuration names.
    agent['max_turns'] = agent.pop('max_iterations', agent.get('max_turns', 90))
    agent.pop('system_message', None)  # seeded through the upstream SOUL mechanism
    for key in ('max_tokens', 'reasoning_effort', 'service_tier'):
        if key in parameters:
            agent.setdefault(key, parameters[key])
    config = {'model': model, 'agent': agent,
              'terminal': {'backend': 'local', 'cwd': '/workspace'},
              'max_turns': agent['max_turns']}
    if document.get('skill_bundle_id'):
        config['skills'] = {'external_dirs': [skills_path]}
    if document['connections']:
        # Bind the default lane to an explicit account-primary identity.
        # Otherwise a named router advertising the same model ID can win the
        # Agent's legacy model-based connection lookup.
        model['provider'] = 'custom:account-primary'
        config['custom_providers'] = [{'name': 'Account primary', 'model': document['model'],
            'base_url': model['base_url'], 'api_key': 'tenant-broker', 'discover_models': True}]
        config['custom_providers'] += [{'name': entry['name'], 'model': entry['model'],
            'base_url': lane + '/providers/' + entry['provider_id'] + '/v1',
            'api_key': 'tenant-broker', 'discover_models': True} for entry in document['connections']]
    return config
