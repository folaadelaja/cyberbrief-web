import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer

from app import fetch, Store, Collector, make_handler, parse_feed, parse_kev, parse_nvd, plain, safe_url, now

RSS = b'''<rss><channel><item><title>Patch CVE-2026-12345 now</title><link>https://example.com/story</link><description>&lt;p&gt;A security patch&lt;/p&gt;&lt;script&gt;evil()&lt;/script&gt;</description><pubDate>Tue, 17 Nov 2026 12:00:00 GMT</pubDate></item><item><title>Bad link</title><link>javascript:alert(1)</link></item></channel></rss>'''
SOURCE = {'id':'test','name':'Test news','kind':'rss','url':'https://example.com/feed'}

class ParserTests(unittest.TestCase):
    def test_rss_plain_text_and_link_safety(self):
        items = parse_feed(RSS, SOURCE)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['summary'], 'A security patch')
        self.assertEqual(items[0]['category'], 'Vulnerabilities')
        self.assertEqual(items[0]['published'], '2026-11-17T12:00:00+00:00')
        self.assertEqual(safe_url('javascript:alert(1)'), '')
        self.assertEqual(safe_url('https://[bad'), '')

    def test_atom_and_missing_dates(self):
        body = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Threat report</title><link href="https://example.com/a"/><summary>New malware</summary></entry></feed>'
        item = parse_feed(body, SOURCE)[0]
        self.assertIsNone(item['published'])
        self.assertEqual(item['url'], 'https://example.com/a')
        self.assertEqual(item['category'], 'Threats')

    def test_invalid_xml_does_not_become_successful_feed(self):
        with self.assertRaises(ValueError):
            parse_feed(b'<html><body>Blocked</body></html>', SOURCE)
        with self.assertRaises(ValueError):
            parse_feed(b'<!DOCTYPE rss [<!ENTITY x "oops">]><rss/>', SOURCE)

    def test_kev_has_exploitation_not_invented_cvss(self):
        row = {'cveID':'CVE-2026-12345','vulnerabilityName':'Test flaw','dateAdded':'2026-11-17','requiredAction':'Patch now','dueDate':'2026-12-01'}
        item = parse_kev(json.dumps({'vulnerabilities':[row]}).encode(), {'id':'cisa'})[0]
        self.assertTrue(item['exploited'])
        self.assertIsNone(item['score'])
        self.assertEqual(item['action'], 'Patch now')

    def test_nvd_prefers_primary_metric_and_ignores_rejected(self):
        cve = {'id':'CVE-2026-12345','published':'2026-11-17T10:00:00.000','descriptions':[{'lang':'en','value':'Test'}], 'metrics':{'cvssMetricV31':[{'type':'Secondary','cvssData':{'baseScore':5.5}},{'type':'Primary','cvssData':{'baseScore':9.8,'baseSeverity':'CRITICAL'}}]}}
        items = parse_nvd({'vulnerabilities':[{'cve':cve},{'cve':dict(cve, vulnStatus='Rejected')}]}, {'id':'nvd'})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['score'], 9.8)
        self.assertFalse(items[0]['exploited'])

class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name))
        self.collector = Collector(self.store, [SOURCE])
    def tearDown(self):
        self.temp.cleanup()

    def test_upsert_retains_content_on_feed_failure(self):
        # Use a missing publication date so fixture does not depend on today's date.
        item = dict(parse_feed(RSS, SOURCE)[0], published=None)
        self.store.save(SOURCE, [item], now())
        self.store.save(SOURCE, [dict(item, title='Updated')], now())
        self.assertEqual(len(self.store.items()), 1)
        success = self.store.status()['test']['last_success']
        with patch('app.fetch', side_effect=TimeoutError('Timed out')):
            self.collector.collect(SOURCE)
        self.assertEqual(self.store.items()[0]['title'], 'Updated')
        self.assertEqual(self.store.status()['test']['last_success'], success)
        self.assertIn('Timed out', self.store.status()['test']['error'])

    def test_transient_upstream_error_is_retried(self):
        import io
        error = HTTPError('https://example.com', 502, 'Bad gateway', {}, io.BytesIO())
        with patch('app.urlopen', side_effect=[error, io.BytesIO(b'ok')]) as upstream, patch('app.time.sleep') as sleep:
            self.assertEqual(fetch('https://example.com'), b'ok')
        self.assertEqual(upstream.call_count, 2)
        sleep.assert_called_once_with(6.5)

    def test_nvd_follows_all_pages(self):
        source = {'id':'nvd','kind':'nvd','name':'NVD','url':'https://example.com/cves'}
        cve = {'id':'CVE-2026-12345','published':now(),'descriptions':[]}
        payloads = [json.dumps({'vulnerabilities':[{'cve':cve}],'resultsPerPage':1,'totalResults':2}).encode(),json.dumps({'vulnerabilities':[{'cve':dict(cve,id='CVE-2026-12346')}],'resultsPerPage':1,'totalResults':2}).encode()]
        with patch('app.fetch', side_effect=payloads) as fetch, patch.object(self.collector.stop, 'wait', return_value=False):
            self.collector.collect(source)
        self.assertEqual(len(self.store.items()), 2)
        self.assertIn('startIndex=1', fetch.call_args_list[1].args[0])
        self.assertIsNone(self.store.status()['nvd']['error'])

    def test_bookmarks_survive_restart_and_feed_retention(self):
        item = dict(parse_feed(RSS, SOURCE)[0], published=None)
        self.store.save(SOURCE, [item], now())
        self.assertTrue(self.store.set_bookmark(item['id'], True))
        with self.store.connect() as db:
            db.execute('DELETE FROM items')
        reopened = Store(Path(self.temp.name))
        self.assertEqual(reopened.bookmarks()['saved_ids'], [item['id']])
        self.assertEqual(reopened.bookmarks()['saved_items'][0]['title'], item['title'])
        self.assertTrue(reopened.set_bookmark(item['id'], False))
        self.assertEqual(reopened.bookmarks()['saved_ids'], [])

    def test_cve_bookmark_combines_nvd_score_and_kev_exploitation(self):
        cve = 'CVE-2026-12345'
        item = dict(parse_feed(RSS, SOURCE)[0], id='nvd:' + cve, kind='cve', cve=cve, source='nvd', score=9.8, published=None)
        self.store.save({'id':'nvd'}, [item], now())
        self.store.save({'id':'cisa'}, [dict(item, id='kev:' + cve, source='cisa', score=None, exploited=True, title='Exploited flaw')], now())
        self.assertTrue(self.store.set_bookmark('cve:' + cve, True))
        snapshot = self.store.bookmarks()['saved_items'][0]
        self.assertTrue(snapshot['exploited'])
        self.assertEqual(snapshot['score'], 9.8)
        self.assertEqual(snapshot['title'], 'Exploited flaw')

    def test_two_clients_share_bookmark_add_remove_and_import(self):
        from urllib.request import build_opener
        item = dict(parse_feed(RSS, SOURCE)[0], published=None)
        self.store.save(SOURCE, [item, dict(item, id='other', title='Another article')], now())
        server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.store, self.collector))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = 'http://127.0.0.1:' + str(server.server_port)
        a, b = build_opener(), build_opener()
        def post(client, path, body, origin=None):
            headers = {'Content-Type':'application/json','X-CyberBrief':'bookmarks'}
            if origin: headers['Origin'] = origin
            with client.open(Request(base + path, data=json.dumps(body).encode(), headers=headers)) as response:
                return json.load(response)
        try:
            post(a, '/api/bookmarks', {'id':item['id'], 'saved':True})
            with b.open(base + '/api/bookmarks') as response:
                self.assertEqual(json.load(response)['saved_ids'], [item['id']])
            post(b, '/api/bookmarks/import', {'ids':['other', item['id']]})
            post(a, '/api/bookmarks', {'id':item['id'], 'saved':False})
            with b.open(base + '/api/bookmarks') as response:
                self.assertEqual(json.load(response)['saved_ids'], ['other'])
            with self.assertRaises(HTTPError) as error:
                post(a, '/api/bookmarks', {'id':'other','saved':False}, 'https://attacker.test')
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
            with self.assertRaises(HTTPError) as error:
                post(a, '/api/bookmarks', {'id':'other','saved':'false'})
            self.assertEqual(error.exception.code, 400)
            error.exception.close()
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_refresh_rate_limit(self):
        import time
        self.assertTrue(self.collector.request_refresh())
        self.collector.last_started = time.time()
        self.assertFalse(self.collector.request_refresh())

    def test_http_routes_and_refresh_origin(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.store, self.collector))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = 'http://127.0.0.1:' + str(server.server_port)
        try:
            with urlopen(base + '/') as r:
                self.assertEqual(r.status, 200)
                html = r.read()
                self.assertIn(b'CyberBrief', html)
                self.assertIn(b'class="brand-owner">fola', html)
                self.assertIn(b'<body class="dark">', html)
                self.assertIn(b'data-stat="news"', html)
                self.assertLess(html.index(b'class="threat-radar'), html.index(b'class="stats"'))
                self.assertIn("frame-src 'none'", r.headers['Content-Security-Policy'])
                self.assertNotIn(b'<iframe', html)
                self.assertIn(b'id="native-world"', html)
                self.assertIn("script-src 'self'", r.headers['Content-Security-Policy'])
            with urlopen(base + '/api/dashboard') as r:
                body = json.load(r)
                self.assertEqual(body['items'], [])
                self.assertEqual(body['sources'][0]['id'], 'test')
            with self.assertRaises(HTTPError) as result:
                urlopen(Request(base + '/api/refresh', method='POST', headers={'Origin':'https://attacker.test','X-CyberBrief':'refresh'}))
            self.assertEqual(result.exception.code, 403)
            result.exception.close()
            with urlopen(Request(base + '/api/refresh', method='POST', headers={'X-CyberBrief':'refresh'})) as r:
                self.assertEqual(r.status, 202)
            with self.assertRaises(HTTPError) as result:
                urlopen(base + '/../../app.py')
            self.assertEqual(result.exception.code, 404)
            result.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

if __name__ == '__main__':
    unittest.main()
