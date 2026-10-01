"""Use the shared VNC web proxy for visible main browsers only."""
import argparse
from pathlib import Path

def patch(source):
    anchor = '        if visible_login:\n            args, ignored_defaults = visible_browser_extension_options(\n'
    replacement = '        if visible_login:\n            kwargs["proxy"] = {"server": os.getenv("VNC_PROXY_SERVER", "http://172.19.240.1:18088")}\n            args, ignored_defaults = visible_browser_extension_options(\n'
    if source.count(anchor) != 1:
        raise ValueError('expected one visible main browser anchor')
    source = source.replace(anchor, replacement, 1)
    compile(source, 'browser.py', 'exec')
    return source

if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('source', type=Path); a = p.parse_args()
    a.source.write_text(patch(a.source.read_text()))
