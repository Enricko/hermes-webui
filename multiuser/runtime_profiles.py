"""Server-owned mapping from granted capabilities to native private profiles.

The root operator publishes this metadata outside the worker's mounts. Browser
cookies select only a granted profile inside the authenticated account runtime.
"""

import json
import re
import stat
from urllib.parse import unquote

from multiuser.store import PolicyError, identifier

PREFIX = 'assigned-'


def profile_name(template_id):
    return PREFIX + identifier(template_id)


def operator_plan(settings, user):
    path = settings.runtime_dir(user['id']) / 'profiles.json'
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PolicyError('Native profile mapping is not operator-owned')
        value = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    return value


def read_plan(settings, user):
    value = operator_plan(settings, user)
    if not value or value.get('auth_version') != user['auth_version']:
        return None
    anchor = identifier(value['anchor'])
    names = {identifier(tid): ('default' if tid == anchor else profile_name(tid))
             for tid in value['profiles'] if tid in user['template_ids']}
    if names != value['profiles']:
        return None
    return {**value, 'profiles': names}


def selected_profile(user, plan, cookie=None):
    """Resolve a native cookie without treating it as account identity."""
    if not plan:
        return user['template_id'], cookie or 'default'
    names = plan['profiles']
    name = unquote(cookie) if cookie else names.get(user['template_id'], next(iter(names.values()), 'default'))
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', name):
        raise PolicyError('Invalid private profile name')
    if name.startswith(PREFIX) and name not in names.values():
        raise PolicyError('Profile is not assigned to this account')
    if name == 'default' and plan['anchor'] not in names:
        name = names.get(user['template_id'], next(iter(names.values()), 'default'))
    tid = next((tid for tid, native in names.items() if native == name), user['template_id'])
    return tid, name
