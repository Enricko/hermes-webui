#!/usr/bin/env python3
"""Build from committed source only, excluding local configuration and runtime data."""

import argparse
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Write immutable image IDs here')
    parser.add_argument('--agent-revision', default='278aeffe16945e7b1405e3c471ad08553c059237')
    parser.add_argument('--python-image', default='python:3.14-slim@sha256:af8a5aa14780025dbfbcfbc81bd8a91ebd87711dd5b0f48ed71090949dd7cb1d')
    args = parser.parse_args()
    import re
    if not re.fullmatch(r'[0-9a-f]{40}', args.agent_revision) or '@sha256:' not in args.python_image:
        parser.error('Pin a full Agent SHA and Python image digest')
    root = Path(__file__).resolve().parent.parent
    version = subprocess.check_output(['git', 'describe', '--tags', '--always', 'HEAD'], cwd=root, text=True).strip()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    with tempfile.TemporaryDirectory(prefix='hermes-mu-build-') as work:
        work = Path(work)
        archive = work / 'source.tar'
        subprocess.run(['git', 'archive', '--format=tar', '--output=' + str(archive), commit], cwd=root, check=True)
        context = work / 'source'
        context.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(context, filter='data')
        # Only committed source, no ignored .env, .venv or local data. Docker's
        # upstream ignore file does not remove the new multiuser package.
        images = {}
        for target in ('relay', 'worker'):
            iid = work / (target + '.iid')
            subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'build',
                            '--target', target, '-f', 'multiuser/Dockerfile',
                            '--build-arg', 'PYTHON_IMAGE=' + args.python_image,
                            '--build-arg', 'AGENT_REV=' + args.agent_revision,
                            '--build-arg', 'WEBUI_VERSION=' + version,
                            '--iidfile', str(iid), str(context)], check=True)
            images[target + '_image'] = iid.read_text().strip()
        images.update({'source_commit': commit, 'agent_revision': args.agent_revision,
                       'python_image': args.python_image})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(images, indent=2) + '\n')
    print(json.dumps(images))


if __name__ == '__main__':
    main()
