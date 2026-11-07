"""Account-owned profile/provider grants, independent of the active selection."""

import json
import re

from multiuser.store import PolicyError, identifier


def identifiers(value, label, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        raise PolicyError(f'Select at most {maximum} {label}')
    values = [identifier(item) for item in value]
    if len(set(values)) != len(values):
        raise PolicyError(f'Duplicate {label}')
    return values


def read(db, user):
    row = db.execute('SELECT template_ids,provider_ids FROM account_access WHERE user_id=?', (user['id'],)).fetchone()
    if row:
        return {'template_ids': identifiers(json.loads(row['template_ids']), 'profiles', 32),
                'provider_ids': identifiers(json.loads(row['provider_ids']), 'providers', 16), 'access_managed': True}
    # Legacy accounts retain their existing profile connections and override.
    # Their grants remain inherited until an admin explicitly saves access.
    templates = [user['template_id']] if user['template_id'] else []
    providers = [user['provider_id']] if user['provider_id'] else []
    if templates:
        template = db.execute('SELECT document FROM templates WHERE id=?', (templates[0],)).fetchone()
        if template:
            document = json.loads(template['document'])
            providers.extend([document['provider_id'], *[p['provider_id'] for p in document.get('connections', [])]])
    return {'template_ids': templates, 'provider_ids': list(dict.fromkeys(providers)), 'access_managed': False}


def configure(db, uid, template, provider, *, template_ids, provider_ids, explicit_template=False, explicit_provider=False):
    tids = identifiers(template_ids, 'profiles', 32)
    pids = identifiers(provider_ids, 'providers', 16)
    for tid in tids:
        if not db.execute('SELECT 1 FROM templates WHERE id=? AND enabled=1', (tid,)).fetchone():
            raise PolicyError('Select enabled profiles')
    for pid in pids:
        if not db.execute('SELECT 1 FROM providers WHERE id=? AND enabled=1', (pid,)).fetchone():
            raise PolicyError('Select enabled providers')
    if explicit_template and template is not None and template not in tids:
        raise PolicyError('The default profile must be assigned to this account')
    if template not in tids:
        template = tids[0] if tids else None
    if explicit_provider and provider is not None and provider not in pids:
        raise PolicyError('The default provider must be assigned to this account')
    default_provider = None
    if template:
        doc = json.loads(db.execute('SELECT document FROM templates WHERE id=?', (template,)).fetchone()['document'])
        default_provider = doc['provider_id']
        if not pids:
            raise PolicyError('Assign at least one provider when assigning profiles')
    selected = provider or default_provider
    if selected not in pids:
        selected = default_provider if default_provider in pids else (pids[0] if pids else None)
    provider = None if selected == default_provider else selected
    db.execute('INSERT INTO account_access VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET '
               'template_ids=excluded.template_ids,provider_ids=excluded.provider_ids',
               (uid, json.dumps(tids), json.dumps(pids)))
    return template, provider


def configured_model(store, pid):
    """Provider-owned model metadata only; no other profile capabilities."""
    with store.connection() as db:
        row = db.execute("SELECT json_extract(c.value,'$.model') AS model FROM templates t, "
            "json_each(t.document,'$.connections') c WHERE t.enabled=1 AND "
            "json_extract(c.value,'$.provider_id')=? ORDER BY t.name LIMIT 1", (pid,)).fetchone()
        if not row:
            row = db.execute("SELECT json_extract(document,'$.model') AS model FROM templates WHERE enabled=1 "
                "AND json_extract(document,'$.provider_id')=? ORDER BY name LIMIT 1", (pid,)).fetchone()
        return row['model'] if row else None


def document(store, user, selected_provider=None):
    """The same server grants drive worker discovery and broker authorization."""
    template = store.template(user['template_id'])
    if user['template_id'] not in user['template_ids']:
        raise PolicyError('Profile is not assigned to this account')
    out = template['document']
    allowed = set(user['provider_ids'])
    primary = user.get('provider_id') or out['provider_id']
    selected = identifier(selected_provider) if selected_provider is not None else primary
    if selected not in allowed:
        raise PolicyError('Provider is not assigned to this account')
    # Own profile capabilities stay intact. Independent provider grants can use
    # registered provider model metadata, without borrowing another profile's
    # instructions, skills or personal state.
    known = {p['provider_id']: dict(p) for p in out['connections']}
    known.setdefault(out['provider_id'], {'provider_id': out['provider_id'], 'model': out['model']})
    for tid in user['template_ids']:
        try:
            other = store.template(tid)['document']
        except PolicyError:
            continue
        known.setdefault(other['provider_id'], {'provider_id': other['provider_id'], 'model': other['model']})
        for connection in other['connections']:
            known.setdefault(connection['provider_id'], dict(connection))
    connections, names = [], set()
    for pid in user['provider_ids']:
        try:
            provider = store.provider(pid)
        except PolicyError:
            if pid == selected:
                raise
            continue
        connection = known.get(pid)
        if connection is None:
            connection = {'provider_id': pid, 'model': configured_model(store, pid) or out['model']}
        name = re.sub(r'[^A-Za-z0-9 ._-]', ' ', connection.get('name', provider['name'])).strip()
        if not name or not name[0].isalnum():
            name = 'Provider ' + name
        name = name[:70]
        slug = re.sub(r'[^a-z0-9._-]+', '-', name.lower()).strip('-')
        if slug in names or slug == 'account-primary':
            name += ' ' + pid[:8]
        names.add(re.sub(r'[^a-z0-9._-]+', '-', name.lower()).strip('-'))
        connections.append({'provider_id': pid, 'name': name, 'model': connection['model']})
    chosen = next(p for p in connections if p['provider_id'] == selected)
    if selected != out['provider_id'] or user.get('provider_id') is not None or selected_provider is not None:
        out.update(model=chosen['model'], models=[chosen['model']])
    out.update(provider_id=selected, connections=connections)
    return template
