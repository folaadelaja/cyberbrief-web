"""CyberBrief: a dependency-free, self-hosted cybersecurity feed reader."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import hashlib
import json
import logging
import os
import re
import signal
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from radar import Radar

ROOT = Path(__file__).resolve().parent
DATA = Path(os.getenv('DATA_DIR', ROOT / 'data'))
INTERVAL = max(300, int(os.getenv('REFRESH_SECONDS', '3600')))
MAX_BODY = 32 * 1024 * 1024
UTC = timezone.utc
log = logging.getLogger('cyberbrief')


def now():
    return datetime.now(UTC).isoformat()


def date(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        try:
            dt = parsedate_to_datetime(value)
        except (ValueError, TypeError, OverflowError):
            return None
    return dt.replace(tzinfo=UTC).isoformat() if dt.tzinfo is None else dt.astimezone(UTC).isoformat()


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag in ('p', 'br', 'div', 'li'):
            self.parts.append(' ')

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.hidden:
            self.hidden -= 1
        self.parts.append(' ')

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def plain(value, limit=600):
    parser = PlainText()
    parser.feed(value or '')
    return re.sub(r'\s+', ' ', ''.join(parser.parts)).strip()[:limit]


def safe_url(value):
    value = (value or '').strip()
    try:
        parsed = urlsplit(value)
        return value if parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username else ''
    except ValueError:
        return ''


def category(text):
    text = text.lower()
    for label, pattern in [('Ransomware', r'ransomware|extortion'), ('Vulnerabilities', r'cve-\d|vulnerabilit|zero.day|patch'), ('Threats', r'malware|phishing|botnet|trojan|espionage|threat actor'), ('Breaches', r'breach|data leak|stolen|hack')]:
        if re.search(pattern, text):
            return label
    return 'Security news'


def parse_feed(body, source):
    # Reject declarations before ElementTree can expand XML entities.
    if re.search(br'<!\s*(DOCTYPE|ENTITY)', body, re.I):
        raise ValueError('XML declarations are not supported')
    root = ET.fromstring(body)
    entries = root.findall('.//item') or root.findall('{http://www.w3.org/2005/Atom}entry')
    if not entries and root.tag.split('}')[-1] not in ('rss', 'feed', 'RDF'):
        raise ValueError('Response is not an RSS or Atom feed')
    items = []
    for entry in entries[:150]:
        fields = {}
        links = []
        for child in entry:
            key = child.tag.split('}')[-1]
            fields.setdefault(key, ''.join(child.itertext()))
            if key == 'link' and child.get('rel', 'alternate') == 'alternate':
                links.append(child.get('href') or child.text or '')
        url = next((safe_url(link) for link in links if safe_url(link)), '')
        title = plain(fields.get('title', ''), 300)
        if not url or not title:
            continue
        summary = plain(fields.get('description') or fields.get('summary') or fields.get('encoded') or fields.get('content', ''))
        items.append(dict(id=hashlib.sha256(url.encode()).hexdigest()[:24], source=source['id'], kind='news', title=title, url=url, summary=summary, published=date(fields.get('pubDate') or fields.get('published') or fields.get('updated') or fields.get('date')), category=category(title + ' ' + summary), cve=None, score=None, severity=None, exploited=False))
    return items


def parse_kev(body, source):
    items = []
    for row in json.loads(body)['vulnerabilities']:
        cve = row['cveID']
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
            continue
        items.append(dict(id='kev:' + cve, source=source['id'], kind='cve', title=row['vulnerabilityName'], url='https://nvd.nist.gov/vuln/detail/' + cve, summary=row.get('shortDescription', ''), published=date(row['dateAdded']), category='Vulnerabilities', cve=cve, score=None, severity=None, exploited=True, vendor=row.get('vendorProject'), product=row.get('product'), action=row.get('requiredAction'), due=row.get('dueDate'), ransomware=row.get('knownRansomwareCampaignUse') == 'Known'))
    return items


def parse_nvd(payload, source):
    items = []
    for row in payload['vulnerabilities']:
        c = row['cve']
        if c.get('vulnStatus') == 'Rejected':
            continue
        metrics = c.get('metrics', {})
        candidates = next((metrics[k] for k in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2') if metrics.get(k)), [])
        metric = next((m for m in candidates if m.get('type') == 'Primary'), candidates[0] if candidates else {})
        cvss = metric.get('cvssData', {})
        score = cvss.get('baseScore')
        summary = next((d['value'] for d in c.get('descriptions', []) if d['lang'] == 'en'), '')
        items.append(dict(id='nvd:' + c['id'], source=source['id'], kind='cve', title=c['id'], url='https://nvd.nist.gov/vuln/detail/' + c['id'], summary=summary, published=date(c.get('published')), modified=date(c.get('lastModified')), category='Vulnerabilities', cve=c['id'], score=score, severity=cvss.get('baseSeverity') or metric.get('baseSeverity'), exploited=False))
    return items


def fetch(url, headers=None):
    request = Request(url, headers={'User-Agent': 'CyberBrief/1.0 (+self-hosted RSS reader)', 'Accept': 'application/json, application/rss+xml, application/atom+xml, application/xml, text/xml', **(headers or {})})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=25) as response:
                body = response.read(MAX_BODY + 1)
            break
        except HTTPError as exc:
            if exc.code not in (429, 502, 503, 504) or attempt == 2:
                exc.close()
                raise
            retry_after = exc.headers.get('Retry-After', '')
            delay = min(60, max(6.5 * (attempt + 1), int(retry_after) if retry_after.isdigit() else 0))
            exc.close()
            time.sleep(delay)
    if len(body) > MAX_BODY:
        raise ValueError('Feed exceeded 32 MB limit')
    return body


class Store:
    def __init__(self, directory=DATA):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / 'cyberbrief.sqlite3'
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, source TEXT, published TEXT, first_seen TEXT, payload TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, payload TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS bookmarks (id TEXT PRIMARY KEY, payload TEXT NOT NULL, saved_at TEXT NOT NULL)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        try:
            with db:
                yield db
        finally:
            db.close()

    def status(self):
        with self.connect() as db:
            return {key: json.loads(body) for key, body in db.execute('SELECT id, payload FROM sources')}

    def save(self, source, items, started, error=None):
        old = self.status().get(source['id'], {})
        status = dict(source, last_attempt=started, last_success=old.get('last_success'), error=error, count=old.get('count', 0))
        with self.connect() as db:
            if error is None:
                status.update(last_success=started, count=len(items))
                for item in items:
                    db.execute('INSERT INTO items VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET published=excluded.published, payload=excluded.payload', (item['id'], source['id'], item['published'], started, json.dumps(item)))
                # Keep all CISA KEV entries for exploitation enrichment; retain other feeds for 30 days.
                cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
                db.execute("DELETE FROM items WHERE source != 'cisa' AND COALESCE(published,first_seen) < ?", (cutoff,))
            db.execute('INSERT OR REPLACE INTO sources VALUES (?, ?)', (source['id'], json.dumps(status)))

    def items(self):
        with self.connect() as db:
            return [dict(json.loads(body), first_seen=seen) for body, seen in db.execute('SELECT payload, first_seen FROM items ORDER BY COALESCE(published,first_seen) DESC')]


    def bookmarks(self):
        with self.connect() as db:
            rows = db.execute('SELECT id, payload, saved_at FROM bookmarks ORDER BY saved_at DESC, id').fetchall()
        return dict(saved_ids=[row[0] for row in rows], saved_items=[dict(json.loads(row[1]), saved_at=row[2]) for row in rows])

    def set_bookmark(self, key, enabled):
        with self.connect() as db:
            if not enabled:
                db.execute('DELETE FROM bookmarks WHERE id = ?', (key,))
                return True
            if db.execute('SELECT 1 FROM bookmarks WHERE id = ?', (key,)).fetchone():
                return True
            if key.startswith('cve:'):
                cve = key[4:]
                rows = db.execute('SELECT payload FROM items WHERE id IN (?, ?)', ('nvd:' + cve, 'kev:' + cve)).fetchall()
            else:
                rows = db.execute('SELECT payload FROM items WHERE id = ?', (key,)).fetchall()
            if not rows:
                return False
            values = [json.loads(row[0]) for row in rows]
            item = next((v for v in values if v['source'] == 'nvd'), values[0]).copy()
            kev = next((v for v in values if v.get('exploited')), None)
            if kev:
                item.update({k: kev.get(k) for k in ('title', 'action', 'due', 'vendor', 'product', 'ransomware')})
                item.update(exploited=True, kevAdded=kev.get('published'))
            item['sourceIds'] = list(dict.fromkeys(v['source'] for v in values))
            db.execute('INSERT OR IGNORE INTO bookmarks VALUES (?, ?, ?)', (key, json.dumps(item), now()))
        return True


class Collector:
    def __init__(self, store, sources):
        self.store, self.sources = store, sources
        self.wake, self.stop = threading.Event(), threading.Event()
        self.lock = threading.Lock()
        self.running = False
        self.last_started = None
        self.next_run = None

    def collect(self, source):
        started = now()
        try:
            if source['kind'] == 'nvd':
                previous = self.store.status().get(source['id'], {}).get('last_success')
                start = datetime.fromisoformat(previous) - timedelta(hours=1) if previous else datetime.now(UTC) - timedelta(days=7)
                # NVD accepts at most a 120-day range; retention is 30 days.
                start = max(start, datetime.now(UTC) - timedelta(days=30))
                params = dict(lastModStartDate=start.strftime('%Y-%m-%dT%H:%M:%S.000'), lastModEndDate=datetime.fromisoformat(started).strftime('%Y-%m-%dT%H:%M:%S.000'), resultsPerPage=2000, startIndex=0)
                headers = {'apiKey': os.environ['NVD_API_KEY']} if os.getenv('NVD_API_KEY') else {}
                items = []
                while not self.stop.is_set():
                    payload = json.loads(fetch(source['url'] + '?' + urlencode(params), headers))
                    items.extend(parse_nvd(payload, source))
                    params['startIndex'] += payload['resultsPerPage']
                    if params['startIndex'] >= payload['totalResults']:
                        break
                    if not payload['resultsPerPage']:
                        raise ValueError('NVD returned an empty page before the end')
                    if self.stop.wait(6.5):
                        return
                if self.stop.is_set():
                    return
            else:
                body = fetch(source['url'])
                items = parse_kev(body, source) if source['kind'] == 'kev' else parse_feed(body, source)
            self.store.save(source, items, started)
            log.info('%s: %s items', source['name'], len(items))
        except Exception as exc:
            # Keep earlier content when a publisher is temporarily unavailable.
            log.warning('%s: %s', source['name'], exc)
            self.store.save(source, [], started, str(exc)[:300])

    def request_refresh(self):
        with self.lock:
            if self.running or (self.last_started and time.time() - self.last_started < 300):
                return False
            self.wake.set()
            return True

    def run(self):
        while not self.stop.is_set():
            with self.lock:
                self.wake.clear()
                self.running = True
                self.last_started = time.time()
                self.next_run = None
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(self.collect, self.sources))
            with self.lock:
                self.running = False
                self.next_run = (datetime.now(UTC) + timedelta(seconds=INTERVAL)).isoformat()
            self.wake.wait(INTERVAL)


def make_handler(store, collector, radar=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.info(fmt, *args)

        def respond(self, status, body, content_type='application/json; charset=utf-8'):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == '/api/dashboard':
                statuses = store.status()
                sources = [statuses.get(s['id'], dict(s, last_success=None, error=None, count=0)) for s in collector.sources]
                self.respond(200, dict(items=store.items(), sources=sources, refreshing=collector.running, next_refresh=collector.next_run, interval_seconds=INTERVAL, server_time=now()))
            elif path == '/api/radar':
                self.respond(200, radar.status() if radar else dict(rows=[], countries=[], last_success=None, error=None))
            elif path == '/api/bookmarks':
                self.respond(200, store.bookmarks())
            elif path == '/api/health':
                statuses = store.status()
                self.respond(200, dict(status='ok', refreshing=collector.running, successful_sources=sum(bool(s.get('last_success')) for s in statuses.values())))
            elif path in ('/', '/index.html', '/style.css', '/app.js', '/radar.js', '/world-map.json', '/favicon.svg'):
                name = 'index.html' if path == '/' else path[1:]
                types = {'html': 'text/html', 'css': 'text/css', 'js': 'text/javascript', 'svg': 'image/svg+xml', 'json': 'application/json'}
                self.respond(200, (ROOT / 'static' / name).read_bytes(), types[name.rsplit('.', 1)[1]] + '; charset=utf-8')
            else:
                self.respond(404, {'error': 'Not found'})

        def do_POST(self):
            if self.path not in ('/api/refresh', '/api/bookmarks', '/api/bookmarks/import'):
                return self.respond(404, {'error': 'Not found'})
            origin = self.headers.get('Origin')
            if (origin and urlsplit(origin).netloc != self.headers.get('Host')) or self.headers.get('X-CyberBrief') != ('refresh' if self.path == '/api/refresh' else 'bookmarks'):
                return self.respond(403, {'error': 'Same-origin requests required'})
            if self.path != '/api/refresh':
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 131072:
                        return self.respond(400, {'error': 'Invalid bookmark request size'})
                    payload = json.loads(self.rfile.read(length))
                    if not isinstance(payload, dict):
                        raise ValueError('Expected an object')
                    if self.path.endswith('/import'):
                        ids = payload.get('ids')
                        if not isinstance(ids, list) or len(ids) > 1000:
                            raise ValueError('Expected up to 1000 bookmark IDs')
                        if any(not isinstance(key, str) or not 1 <= len(key) <= 128 for key in ids):
                            raise ValueError('Invalid bookmark ID')
                        missing = [key for key in dict.fromkeys(ids) if not store.set_bookmark(key, True)]
                        return self.respond(200, dict(store.bookmarks(), missing=missing))
                    key, enabled = payload.get('id'), payload.get('saved')
                    if not isinstance(key, str) or not 1 <= len(key) <= 128 or not isinstance(enabled, bool):
                        raise ValueError('Expected bookmark ID and saved boolean')
                    if not store.set_bookmark(key, enabled):
                        return self.respond(404, {'error': 'This article is no longer in the collected feed'})
                    return self.respond(200, store.bookmarks())
                except (ValueError, TypeError):
                    return self.respond(400, {'error': 'Invalid bookmark request'})
            accepted = collector.request_refresh()
            self.respond(202 if accepted else 429, {'accepted': accepted, 'message': 'Refresh queued' if accepted else 'A refresh is running or was started in the last five minutes.'})
    return Handler


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    sources = json.loads(Path(os.getenv('SOURCES_FILE', ROOT / 'sources.json')).read_text())
    ids = set()
    for source in sources:
        if source['id'] in ids or source['kind'] not in ('rss', 'kev', 'nvd') or not safe_url(source['url']):
            raise ValueError('Invalid or duplicate source configuration')
        ids.add(source['id'])
    store = Store()
    collector = Collector(store, sources)
    radar = Radar(store, collector.stop)
    radar_worker = threading.Thread(target=radar.run, daemon=True)
    worker = threading.Thread(target=collector.run, daemon=True)
    server = ThreadingHTTPServer((os.getenv('HOST', '127.0.0.1'), int(os.getenv('PORT', '8080'))), make_handler(store, collector, radar))
    def shutdown(*_):
        collector.stop.set()
        collector.wake.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    worker.start()
    radar_worker.start()
    log.info('CyberBrief listening on http://%s:%s', *server.server_address)
    try:
        server.serve_forever()
    finally:
        collector.stop.set()
        collector.wake.set()
        server.server_close()
        worker.join(timeout=30)
        radar_worker.join(timeout=20)


if __name__ == '__main__':
    main()
