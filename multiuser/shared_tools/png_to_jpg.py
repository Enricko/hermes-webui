#!/usr/bin/env python3
"""Convert a workspace PNG with private job temp files and atomic output creation."""

import argparse
import json
import os
from pathlib import Path
import tempfile

from PIL import Image, ImageColor


def confined(path, root, *, exists=False):
    value = Path(path).resolve(strict=exists)
    if not value.is_relative_to(root) or value == root:
        raise ValueError('Input and output must remain inside the workspace')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--workspace', default='/workspace')
    parser.add_argument('--tmp-dir', default='/tmp')
    parser.add_argument('--quality', type=int, default=95)
    parser.add_argument('--background', default='white')
    parser.add_argument('--overwrite', action='store_true')
    args = parser.parse_args()
    root = Path(args.workspace).resolve(strict=True)
    source = confined(args.input, root, exists=True)
    target = confined(args.output, root)
    if not target.parent.is_dir():
        parser.error('Create the output directory inside your workspace first')
    scratch = Path(args.tmp_dir).resolve(strict=True)
    if not (scratch.is_relative_to(root) or scratch.is_relative_to(Path('/tmp'))):
        parser.error('Use your private /tmp or a workspace job directory for temporary files')
    if not 1 <= args.quality <= 100:
        parser.error('Quality must be between 1 and 100')
    temporary = None
    try:
        with tempfile.TemporaryDirectory(prefix='png-to-jpg-', dir=scratch):
            with Image.open(source) as image:
                if image.format != 'PNG':
                    raise ValueError('Input must be a PNG image')
                rgba = image.convert('RGBA')
                rgb = Image.new('RGB', rgba.size, ImageColor.getrgb(args.background))
                rgb.paste(rgba, mask=rgba.getchannel('A'))
                with tempfile.NamedTemporaryFile(prefix='.png-to-jpg-', suffix='.jpg', dir=target.parent, delete=False) as stream:
                    temporary = Path(stream.name)
                    rgb.save(stream, format='JPEG', quality=args.quality)
                    stream.flush()
                    os.fsync(stream.fileno())
                if args.overwrite:
                    os.replace(temporary, target)
                else:
                    # Atomic no-clobber publication, even for two jobs racing
                    # inside the same account's workspace.
                    os.link(temporary, target)
                print(json.dumps({'output': str(target), 'width': rgb.width, 'height': rgb.height}))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
