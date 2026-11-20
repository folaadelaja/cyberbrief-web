import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from app import Store
from radar import Radar


class RadarTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name))
        self.stop = threading.Event()
        self.radar = Radar(self.store, self.stop)
        self.rows = [dict(source='8.8.8.8', reports=20, targets=2), dict(source='1.1.1.1', reports=10, targets=1)]
        self.geo = dict(success=True, country='United States', country_code='US')

    def tearDown(self):
        self.temp.cleanup()

    def test_real_summary_aggregates_and_caches_geolocation(self):
        with patch('radar.get_json', side_effect=[self.rows, self.geo, self.geo]) as fetch, patch.object(self.stop, 'wait', return_value=False):
            self.radar.collect()
        state = self.radar.status()
        self.assertEqual(state['reports'], 30)
        self.assertEqual(state['countries'], [dict(code='US', name='United States', reports=30, sources=2)])
        self.assertEqual(state['mode'], 'daily-summary')
        self.assertEqual(fetch.call_args_list[0].args[0], 'https://isc.sans.edu/api/topips/records/30?json')
        self.assertEqual(state['window'], 'Latest provider daily summary')
        self.assertNotIn('routes', state)
        with patch('radar.get_json', return_value=self.rows) as fetch, patch.object(self.stop, 'wait', return_value=False):
            self.radar.collect()
        self.assertEqual(fetch.call_count, 1, 'Cached geolocation avoids repeat provider requests')

    def test_feed_failure_preserves_last_successful_snapshot(self):
        with patch('radar.get_json', side_effect=[self.rows, self.geo, self.geo]), patch.object(self.stop, 'wait', return_value=False):
            self.radar.collect()
        previous = self.radar.status()
        with patch('radar.get_json', side_effect=TimeoutError('upstream unavailable')):
            self.radar.collect()
        state = self.radar.status()
        self.assertEqual(state['last_success'], previous['last_success'])
        self.assertEqual(state['rows'], previous['rows'])
        self.assertIn('upstream unavailable', state['error'])

    def test_geolocation_rate_limit_stops_further_lookups(self):
        import io
        error = HTTPError('https://ipwho.is',429,'Too many requests',{},io.BytesIO())
        with patch('radar.get_json', side_effect=[self.rows, error]) as fetch, patch.object(self.stop, 'wait', return_value=False):
            self.radar.collect()
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(self.radar.status()['unmapped_sources'], 2)
        self.assertEqual(self.radar.status()['reports'], 30)
        self.assertEqual(self.radar.status()['countries'], [])


if __name__ == '__main__':
    unittest.main()
