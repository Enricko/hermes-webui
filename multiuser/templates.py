"""Explicit, non-secret capability templates. Personal state is never a template."""

from __future__ import annotations

import copy
from pathlib import PurePosixPath
import re

from multiuser.store import PolicyError, identifier

FIELDS = {"provider_id", "model", "models", "parameters", "agent", "soul", "skills", "tools", "egress_hosts", "skill_bundle_id", "model_catalog"}
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


def worker_config(template):
    """Shared secrets and legacy personal/integration state cannot enter this output."""
    document = validate_template(template)
    model = {'provider': 'custom', 'default': document['model'],
             'base_url': 'http://127.0.0.1:8000/v1',
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
        config['skills'] = {'external_dirs': ['/shared/skills']}
    return config
