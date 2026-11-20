"""Original CyberBrief map: daily DShield summaries, never fabricated live events."""
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import ipaddress
import json
import logging
import threading

UTC = timezone.utc
USER_AGENT = 'CyberBrief/1.0 (https://github.com/folaadelaja/cyberbrief)'


def timestamp():
    return datetime.now(UTC).isoformat()


def get_json(url):
    request = Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'})
    # No immediate retries, especially after 429. Next radar cycle is an hour away.
    with urlopen(request, timeout=15) as response:
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError('Telemetry response too large')
    return json.loads(body)


def summarize(rows):
    countries = {}
    for row in rows:
        if not row.get('country_code'):
            continue
        code = row['country_code']
        entry = countries.setdefault(code, dict(code=code, name=row['country'], reports=0, sources=0))
        entry['reports'] += row['reports']
        entry['sources'] += 1
    return sorted(countries.values(), key=lambda c: (-c['reports'], c['code']))


class Radar:
    def __init__(self, store, stop):
        self.store, self.stop = store, stop
        self.running = False
        with store.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS radar_state (id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS radar_geo (ip TEXT PRIMARY KEY, updated TEXT, payload TEXT NOT NULL)')

    def status(self):
        with self.store.connect() as db:
            row = db.execute("SELECT payload FROM radar_state WHERE id='latest'").fetchone()
        result = json.loads(row[0]) if row else dict(rows=[], countries=[], last_success=None, error=None, window=None)
        return dict(result, refreshing=self.running, refresh_seconds=3600, source='SANS ISC / DShield', geolocation='ipwho.is', mode='daily-summary')

    def location(self, ip):
        with self.store.connect() as db:
            row = db.execute('SELECT updated, payload FROM radar_geo WHERE ip=?', (ip,)).fetchone()
        if row and datetime.fromisoformat(row[0]) > datetime.now(UTC) - timedelta(days=7):
            return json.loads(row[1])
        payload = get_json('https://ipwho.is/' + ip)
        if payload.get('success') is not True or not payload.get('country_code'):
            raise ValueError('Geolocation unavailable')
        location = dict(country_code=str(payload['country_code'])[:2], country=str(payload['country'])[:100])
        with self.store.connect() as db:
            db.execute('INSERT OR REPLACE INTO radar_geo VALUES (?, ?, ?)', (ip, timestamp(), json.dumps(location)))
        return location

    def collect(self):
        self.running = True
        started = timestamp()
        previous = self.status()
        try:
            # This endpoint does not include a report date; expose that limitation rather than inventing one.
            window = 'Latest provider daily summary'
            payload = get_json('https://isc.sans.edu/api/topips/records/30?json')
            if not isinstance(payload, list) or not payload:
                raise ValueError('Daily telemetry is not available yet')
            rows = []
            geo_limited = False
            for item in payload[:30]:
                if self.stop.is_set():
                    return
                ip = str(ipaddress.ip_address(item['source']))
                row = dict(ip=ip, reports=max(0, int(item['reports'])), targets=max(0, int(item['targets'])))
                if not geo_limited:
                    try:
                        row.update(self.location(ip))
                    except HTTPError as exc:
                        geo_limited = exc.code == 429
                        exc.close()
                    except (ValueError, OSError):
                        pass
                rows.append(row)
                if self.stop.wait(0.2):
                    return
            result = dict(rows=rows, countries=summarize(rows), window=window, last_attempt=started, last_success=timestamp(), error=None,
                          reports=sum(row['reports'] for row in rows), unmapped_sources=sum(not row.get('country_code') for row in rows))
        except Exception as exc:
            logging.getLogger('cyberbrief').warning('Radar: %s', exc)
            result = dict(previous, last_attempt=started, error=str(exc)[:200])
        finally:
            self.running = False
        if self.stop.is_set():
            return
        with self.store.connect() as db:
            db.execute("INSERT OR REPLACE INTO radar_state VALUES ('latest', ?)", (json.dumps(result),))

    def run(self):
        while not self.stop.is_set():
            self.collect()
            self.stop.wait(3600)
