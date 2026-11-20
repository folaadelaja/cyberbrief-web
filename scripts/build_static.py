"""Build public, portable CyberBrief snapshots for GitHub Pages (stdlib only)."""
from pathlib import Path
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import re
import shutil
import sys
import threading
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import Store, Collector
from radar import Radar

def stamp():
    return datetime.now(timezone.utc).isoformat()

def build_site(dashboard, radar, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    # Never include reading lists, databases, secrets, or host configuration.
    statuses = [{key: source.get(key) for key in ('id','name','url','kind','last_success','count')} |
                {'error': 'Provider unavailable; cached data retained.' if source.get('error') else None}
                for source in dashboard['sources']]
    payload = dict(items=dashboard['items'], sources=statuses, refreshing=False,
                   interval_seconds=3600, server_time=stamp(), generated_at=stamp(), next_refresh=None)
    radar = {key: radar.get(key) for key in ('rows','countries','window','last_attempt','last_success','reports','unmapped_sources','mode','source','geolocation')}
    radar.update(refreshing=False, refresh_seconds=3600)
    (output/'data').mkdir(exist_ok=True)
    (output/'data/dashboard.json').write_text(json.dumps(payload, separators=(',',':')), encoding='utf-8')
    (output/'data/radar.json').write_text(json.dumps(radar, separators=(',',':')), encoding='utf-8')
    for name in ('style.css','favicon.svg','world-map.json'):
        shutil.copy2(ROOT/'static'/name, output/name)
    html = (ROOT/'static/index.html').read_text()
    for name in ('style.css','favicon.svg','app.js','radar.js'):
        html = html.replace('"/'+name+'"', '"./'+name+'"')
    html = html.replace('class="brand" href="/"', 'class="brand" href="./"')
    html = html.replace('<meta name="color-scheme"', '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data:; connect-src \'self\'; object-src \'none\'; base-uri \'none\'; form-action \'self\'"><meta name="color-scheme"', 1)
    html = html.replace('<div id="notice"', '<p class="static-note">Public edition · news updates hourly on GitHub · saved articles stay in this browser.</p><div id="notice"', 1)
    html = html.replace(' Refresh feeds</button>', ' Check for updates</button>')
    html = html.replace('<div id="items"', '<div id="reading-tools" class="reading-tools" hidden><button id="export-reading" class="button" type="button">Export saved articles</button><label class="button import-reading" tabindex="0">Import saved articles<input id="import-reading" type="file" accept="application/json,.json"></label><span>Use export/import to move your list between devices.</span></div><div id="items"', 1)
    html = html.replace('<footer>', '<footer><a class="button" href="./downloads/cyberbrief-static.zip" download>Download app</a>', 1)
    html = html.replace('Stories and CVEs saved to your shared reading list.', 'Stories and CVEs saved in this browser.')
    (output/'index.html').write_text(html, encoding='utf-8')
    js = (ROOT/'static/app.js').read_text()
    js = js.replace("fetch('/api/dashboard')", "fetch('./data/dashboard.json', {cache:'no-store'})")
    start = js.index('async function bookmarkRequest(')
    end = js.index('async function syncBookmarks()', start)
    adapter = (ROOT/'static/pages-bookmarks.js').read_text()
    js = js[:start] + adapter + '\n' + js[end:]
    start = js.index("$('refresh').addEventListener('click'")
    end = js.index("$('theme-toggle').addEventListener", start)
    js = js[:start] + "$('refresh').addEventListener('click', async () => { await load(); toast('Checked the latest published snapshot. GitHub collects feeds hourly.'); });\n" + js[end:]
    js = js.replace("'Collector online'", "'Published snapshot'")
    old = next(line for line in js.splitlines() if "$('schedule').textContent = data.next_refresh" in line)
    js = js.replace(old, "  $('schedule').textContent = `Published ${fullDate(data.generated_at)} · scheduled hourly · page checks every minute`;")
    js = js.replace("  renderItems();\n}\nfunction openStat", "  $('reading-tools').hidden = view !== 'saved';\n  renderItems();\n}\nfunction openStat", 1)
    js = js.replace('Your saved list syncs across devices using this dashboard.', 'Your list stays in this browser. Export it to transfer it to another device.')
    js = js.replace('Stories and CVEs saved to your shared reading list.', 'Stories and CVEs saved in this browser.')
    js = js.replace('Saved articles are shared across devices.', 'Saved articles stay in this browser; export/import moves them between devices.')
    js = js.replace("const item = mergedCVEs(enabledItems()).find(i => i.cve === cve);", "const item = mergedCVEs(enabledItems()).find(i => i.cve === cve) || savedItems.find(i => i.cve === cve);")
    js = js.replace("'Bookmarks could not sync. Your existing saved list is unchanged.'", "'Your browser could not load saved articles. Check storage settings.'")
    js = js.replace("'Bookmark sync failed'", "'Unable to save in this browser'")
    (output/'app.js').write_text(js, encoding='utf-8')
    radar_js = (ROOT/'static/radar.js').read_text().replace("fetch('/api/radar')", "fetch('./data/radar.json', {cache:'no-store'})").replace("fetch('/world-map.json')", "fetch('./world-map.json')")
    # On static hosting, refresh means checking the published snapshot, not contacting a live radar server.
    radar_js = radar_js.replace('Radar server unavailable', 'Published telemetry unavailable').replace('Public telemetry connected', 'Published daily telemetry')
    (output/'radar.js').write_text(radar_js, encoding='utf-8')
    with (output/'style.css').open('a') as style:
        style.write('\n.static-note{font-size:.8125rem;color:var(--muted);margin:-8px 0 20px}.reading-tools{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:16px 0}.reading-tools>span{font-size:.8125rem;color:var(--muted)}.import-reading{position:relative;cursor:pointer;overflow:hidden}.import-reading input{position:absolute;inset:0;opacity:0;width:100%;cursor:pointer}.import-reading:focus-within{outline:2px solid var(--green);outline-offset:3px}\n')
    (output/'.nojekyll').write_text('')
    (output/'README.txt').write_text('CyberBrief static web app\n\nServe this folder using any static web host, or run:\n  python3 -m http.server 8080\nThen visit http://localhost:8080\n\nThis download contains the snapshot published at '+payload['generated_at']+'. Download a new copy for newer data, or use the included source repository workflow for scheduled updates. Opening index.html directly from disk will not load JSON in browsers that block file requests.\n\nSaved articles are stored in this browser. Use Reading list > Export/Import to move them between devices. No login is required. The original self-hosted server edition supports shared saved articles.\n\nSource and updater: https://github.com/folaadelaja/cyberbrief-web\nData: SANS ISC / DShield, ipwho.is, Natural Earth, NVD, CISA, and the credited news publishers.\n', encoding='utf-8')
    downloads = output/'downloads'; downloads.mkdir(exist_ok=True)
    archive = downloads/'cyberbrief-static.zip'
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as bundle:
        for file in sorted(output.rglob('*')):
            if file.is_file() and downloads not in file.parents:
                bundle.write(file, file.relative_to(output))
    print('Built', output, '| articles/CVEs:', len(payload['items']), '| download bytes:', archive.stat().st_size)
    return payload

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='dist')
    parser.add_argument('--cache', default='data')
    args = parser.parse_args()
    store = Store(Path(args.cache))
    sources = json.loads((ROOT/'sources.json').read_text())
    collector = Collector(store, sources)
    radar = Radar(store, threading.Event())
    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs = [pool.submit(collector.collect, source) for source in sources]
        jobs.append(pool.submit(radar.collect))
        for job in jobs: job.result()
    statuses = store.status()
    dashboard = dict(items=store.items(), sources=[statuses.get(source['id'], dict(source,last_success=None,error='Not collected',count=0)) for source in sources])
    if not dashboard['items']:
        raise SystemExit('No collected or cached items; preserving the previous deployed site.')
    build_site(dashboard, radar.status(), args.output)

if __name__ == '__main__':
    main()
