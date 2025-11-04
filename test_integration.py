#!/usr/bin/env python3
"""
Testy integracyjne dla vpn_adbocker
Testują przetwarzanie rzeczywistych payloadów HTTP/HTTPS
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_adbocker import YouTubeAdBlocker, AdClassifier
from test_payloads import get_all_payloads
import logging

# Wyłącz logowanie dla testów
logging.disable(logging.CRITICAL)


class TestPayloadProcessing(unittest.TestCase):
    """Testy przetwarzania payloadów"""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja przed testami"""
        cls.classifier = AdClassifier('ad_signatures.json')
    
    def extract_url_from_payload(self, payload_data):
        """Wyciągnij URL z payloadu HTTP"""
        try:
            # Szukaj metody HTTP i URL
            http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ']
            for method in http_methods:
                if method in payload_data:
                    start = payload_data.find(method) + len(method)
                    end = payload_data.find(b' HTTP/', start)
                    if end > start:
                        url = payload_data[start:end].decode('utf-8', errors='ignore')
                        
                        # Wyciągnij hosta
                        host_start = payload_data.find(b'Host: ')
                        if host_start >= 0:
                            host_start += 6
                            host_end = payload_data.find(b'\r\n', host_start)
                            if host_end > host_start:
                                host = payload_data[host_start:host_end].decode('utf-8', errors='ignore')
                                
                                # Zbuduj pełny URL
                                if not url.startswith('http'):
                                    if url.startswith('/'):
                                        url = f"http://{host}{url}"
                                    else:
                                        url = f"http://{host}/{url}"
                                
                                return url
        except Exception as e:
            pass
        
        return None
    
    def test_ad_payloads_blocked(self):
        """Test że wszystkie payloady reklamowe są rozpoznawane"""
        payloads = get_all_payloads()
        ad_payloads = [p for p in payloads if p['is_ad'] and p['type'] == 'http']
        
        blocked_count = 0
        failed = []
        
        for payload in ad_payloads:
            url = self.extract_url_from_payload(payload['data'])
            
            if url:
                result = self.classifier.classify_ad(url)
                if result:
                    blocked_count += 1
                else:
                    failed.append((payload['name'], url))
        
        print(f"\nZablokowano {blocked_count}/{len(ad_payloads)} payloadów reklamowych")
        
        if failed:
            print("\nNie zablokowano:")
            for name, url in failed:
                print(f" - {name}: {url[:80]}...")
        
        # Sprawdź że większość została zablokowana (>90%)
        success_rate = blocked_count / len(ad_payloads) if ad_payloads else 0
        self.assertGreaterEqual(success_rate, 0.9, 
                               f"Zbyt niski współczynnik blokowania reklam: {success_rate:.2%}")
    
    def test_normal_payloads_not_blocked(self):
        """Test że zwykłe wideo nie jest blokowane (brak fałszywych trafień)"""
        payloads = get_all_payloads()
        normal_payloads = [p for p in payloads if not p['is_ad'] and p['type'] == 'http']
        
        false_positives = []
        
        for payload in normal_payloads:
            url = self.extract_url_from_payload(payload['data'])
            
            if url:
                result = self.classifier.classify_ad(url)
                if result:
                    false_positives.append((payload['name'], url, result))
        
        if false_positives:
            print(f"\n⚠️  FAŁSZYWE TRAFIENIA ({len(false_positives)}):")
            for name, url, result in false_positives:
                print(f" - {name}: {url[:80]}...")
                print(f"   Sklasyfikowano jako: {result}")
        
        self.assertEqual(len(false_positives), 0, 
                        f"Wykryto {len(false_positives)} fałszywych trafień!")
    
    def test_classification_details(self):
        """Test szczegółów klasyfikacji dla różnych typów reklam"""
        test_cases = [
            {
                'url': 'https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=0&ctier=L',
                'expected_type': 'pre-roll',
                'expected_skippable': True
            },
            {
                'url': 'https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=1&adgoogleid=xyz',
                'expected_type': 'mid-roll',
                'expected_skippable': True
            },
            {
                'url': 'https://www.youtube.com/api/stats/ads?postroll=true',
                'expected_type': 'post-roll',
                'expected_skippable': None  # Może być różnie
            },
            {
                'url': 'https://www.youtube.com/pagead/interaction/?ad_format=overlay',
                'expected_type': 'overlay',
                'expected_skippable': True
            },
        ]
        
        for test in test_cases:
            with self.subTest(url=test['url']):
                result = self.classifier.classify_ad(test['url'])
                self.assertIsNotNone(result, f"Nie rozpoznano: {test['url']}")
                
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, test['expected_type'], 
                               f"Nieprawidłowy typ dla: {test['url']}")
                
                if test['expected_skippable'] is not None:
                    self.assertEqual(is_skippable, test['expected_skippable'],
                                   f"Nieprawidłowa wartość skippable dla: {test['url']}")


class TestStatisticsTracking(unittest.TestCase):
    """Testy śledzenia statystyk"""
    
    def test_stats_tracking(self):
        """Test czy statystyki są prawidłowo śledzone"""
        from vpn_adbocker import Stats
        
        stats = Stats()
        
        # Symuluj różne typy reklam
        stats.add_packet(is_blocked=True, domain='doubleclick.net', 
                        ad_type='pre-roll', ad_name='pre_roll_skippable', is_skippable=True)
        stats.add_packet(is_blocked=True, domain='googlesyndication.com',
                        ad_type='mid-roll', ad_name='mid_roll_skippable', is_skippable=True)
        stats.add_packet(is_blocked=True, domain='googleadservices.com',
                        ad_type='pre-roll', ad_name='pre_roll_nonskippable', is_skippable=False)
        stats.add_packet(is_blocked=True, domain='youtube.com',
                        ad_type='overlay', ad_name='overlay_banner', is_skippable=True)
        stats.add_packet(is_blocked=False)  # Zwykły pakiet
        
        # Sprawdź statystyki
        self.assertEqual(stats.total_packets, 5)
        self.assertEqual(stats.blocked_packets, 4)
        self.assertEqual(stats.blocked_preroll, 2)
        self.assertEqual(stats.blocked_midroll, 1)
        self.assertEqual(stats.blocked_overlay, 1)
        self.assertEqual(stats.blocked_skippable, 3)
        self.assertEqual(stats.blocked_nonskippable, 1)
    
    def test_stats_by_pattern(self):
        """Test statystyk według wzorca"""
        from vpn_adbocker import Stats
        
        stats = Stats()
        
        # Symuluj różne wzorce
        for _ in range(3):
            stats.add_packet(is_blocked=True, ad_name='pre_roll_skippable')
        for _ in range(5):
            stats.add_packet(is_blocked=True, ad_name='mid_roll_skippable')
        for _ in range(2):
            stats.add_packet(is_blocked=True, ad_name='overlay_banner')
        
        self.assertEqual(stats.blocked_by_pattern['pre_roll_skippable'], 3)
        self.assertEqual(stats.blocked_by_pattern['mid_roll_skippable'], 5)
        self.assertEqual(stats.blocked_by_pattern['overlay_banner'], 2)


class TestURLNormalization(unittest.TestCase):
    """Testy normalizacji URL"""
    
    @classmethod
    def setUpClass(cls):
        cls.classifier = AdClassifier('ad_signatures.json')
    
    def test_url_decoding(self):
        """Test dekodowania URL"""
        encoded_url = "https://example.com/path?param1=value%201&param%5F2=test"
        base_url, params = self.classifier.normalize_url(encoded_url)
        
        self.assertIn('param1', params)
        self.assertEqual(params['param1'], 'value 1')
        self.assertIn('param_2', params)
    
    def test_parameter_extraction(self):
        """Test wyciągania parametrów"""
        url = "https://googlevideo.com/videoplayback?oad=1&adpodposition=2&ctier=L&dur=30"
        base_url, params = self.classifier.normalize_url(url)
        
        self.assertEqual(params['oad'], '1')
        self.assertEqual(params['adpodposition'], '2')
        self.assertEqual(params['ctier'], 'L')
        self.assertEqual(params['dur'], '30')
    
    def test_heuristics_extraction(self):
        """Test wyciągania heurystyk"""
        url = "https://googlevideo.com/videoplayback?oad=1&adpodposition=3&ctier=L&ad_type=video"
        base_url, params = self.classifier.normalize_url(url)
        heuristics = self.classifier.extract_heuristics(url, params)
        
        self.assertTrue(heuristics['has_oad_flag'])
        self.assertTrue(heuristics['has_ctier_l'])
        self.assertTrue(heuristics['has_ad_type'])
        self.assertEqual(heuristics['adpodposition'], 3)


def run_tests():
    """Uruchom wszystkie testy integracyjne"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Dodaj wszystkie testy
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadProcessing))
    suite.addTests(loader.loadTestsFromTestCase(TestStatisticsTracking))
    suite.addTests(loader.loadTestsFromTestCase(TestURLNormalization))
    
    # Uruchom testy
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Wyświetl podsumowanie
    print("\n" + "=" * 70)
    print("PODSUMOWANIE TESTÓW INTEGRACYJNYCH")
    print("=" * 70)
    print(f"Uruchomiono testów: {result.testsRun}")
    print(f"Sukces: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Niepowodzenia: {len(result.failures)}")
    print(f"Błędy: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ Wszystkie testy integracyjne przeszły pomyślnie!")
        return 0
    else:
        print("\n❌ Niektóre testy integracyjne nie powiodły się!")
        return 1


if __name__ == '__main__':
    sys.exit(run_tests())
