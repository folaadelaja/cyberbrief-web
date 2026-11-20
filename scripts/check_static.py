"""Verify a Pages package without contacting upstream providers."""
from pathlib import Path
from html.parser import HTMLParser
import json
import re
import sys
import zipfile
root = Path(sys.argv[1] if len(sys.argv)>1 else 'dist')
class Check(HTMLParser):
    def __init__(self): super().__init__(); self.ids=[]; self.assets=[]
    def handle_starttag(self,tag,attrs):
        data=dict(attrs)
        if 'id' in data:self.ids.append(data['id'])
        if tag in ('script','link'):
            value=data.get('src') or data.get('href','')
            if value:self.assets.append(value)
check=Check(); html=(root/'index.html').read_text(); check.feed(html)
assert len(check.ids)==len(set(check.ids)), 'Duplicate HTML IDs'
for asset in check.assets:
    assert asset.startswith('./'), 'Assets must work under a project subpath'
    assert (root/asset).is_file(), asset
js=(root/'app.js').read_text(); radar=(root/'radar.js').read_text()
assert not re.search(r"fetch\('/api/",js+radar), 'Static app must not call live API routes'
assert "fetch('./data/dashboard.json'" in js
assert "fetch('./data/radar.json'" in radar
assert "fetch('./world-map.json')" in radar
assert 'id="reading-tools"' in html and 'id="export-reading"' in html
assert "$('reading-tools').hidden = view !== 'saved'" in js
assert not (set(re.findall(r"\$\('([^']+)'\)",js))-set(check.ids)), 'Missing script targets'
dashboard=json.loads((root/'data/dashboard.json').read_text())
assert dashboard['items'] and dashboard['generated_at']
assert 'saved_items' not in dashboard and 'saved_ids' not in dashboard
with zipfile.ZipFile(root/'downloads/cyberbrief-static.zip') as archive:
    assert archive.testzip() is None
    assert 'index.html' in archive.namelist() and 'README.txt' in archive.namelist()
    assert not any('sqlite' in name or name.endswith('.env') or name.startswith('downloads/') for name in archive.namelist())
print('Static checks passed: project-subpath assets, snapshot routes, bookmarks controls, script targets, privacy, and ZIP integrity.')
