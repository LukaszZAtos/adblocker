#!/usr/bin/env python3
"""
Testy jednostkowe dla klasyfikatora reklam YouTube
Weryfikują poprawność rozpoznawania różnych typów reklam bez fałszywych trafień
"""

import unittest
import sys
import os
import json

# Dodaj ścieżkę do modułu vpn_adbocker
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_adbocker import AdClassifier


class TestAdClassifier(unittest.TestCase):
    """Testy klasyfikatora reklam YouTube"""
    
    @classmethod
    def setUpClass(cls):
        """Inicjalizacja klasyfikatora przed testami"""
        cls.classifier = AdClassifier('ad_signatures.json')
    
    def test_preroll_skippable_classification(self):
        """Test rozpoznawania reklam pre-roll skippable"""
        test_urls = [
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?id=abc123&oad=1&adpodposition=0&ctier=L",
            "https://www.youtube.com/api/stats/ads?preroll=true&ad_type=video_click_to_play",
            "https://r3.sn-4g5e6nzz.googlevideo.com/videoplayback?oad=1&adpodposition=0&ad_break_type=1"
        ]
        
        for url in test_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy pre-roll: {url}")
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, 'pre-roll', f"Nieprawidłowy typ dla: {url}")
                self.assertTrue(is_skippable, f"Powinna być skippable: {url}")
    
    def test_preroll_nonskippable_classification(self):
        """Test rozpoznawania reklam pre-roll non-skippable"""
        test_urls = [
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=0&ad_break_type=2&ctier=L",
            "https://www.youtube.com/api/stats/ads?preroll=true&nonskip=1&ctier=L"
        ]
        
        for url in test_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy pre-roll non-skippable: {url}")
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, 'pre-roll', f"Nieprawidłowy typ dla: {url}")
                self.assertFalse(is_skippable, f"Powinna być non-skippable: {url}")
    
    def test_midroll_skippable_classification(self):
        """Test rozpoznawania reklam mid-roll skippable"""
        test_urls = [
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=1&adgoogleid=xyz123",
            "https://www.youtube.com/get_midroll_info?ei=abc&ad_type=video",
            "https://r3.sn-4g5e6nzz.googlevideo.com/videoplayback?oad=1&adpodposition=2&ctier=L"
        ]
        
        for url in test_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy mid-roll: {url}")
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, 'mid-roll', f"Nieprawidłowy typ dla: {url}")
                self.assertTrue(is_skippable, f"Powinna być skippable: {url}")
    
    def test_midroll_nonskippable_classification(self):
        """Test rozpoznawania reklam mid-roll non-skippable"""
        test_urls = [
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=1&nonskip=1",
            "https://www.youtube.com/api/stats/ads?midroll=true&bumper=1&ctier=L"
        ]
        
        for url in test_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy mid-roll non-skippable: {url}")
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, 'mid-roll', f"Nieprawidłowy typ dla: {url}")
                self.assertFalse(is_skippable, f"Powinna być non-skippable: {url}")
    
    def test_postroll_classification(self):
        """Test rozpoznawania reklam post-roll"""
        test_urls = [
            "https://www.youtube.com/api/stats/ads?postroll=true&ad_type=video",
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&ad_break_type=3",
            "https://www.youtube.com/api/stats/playback/post_playback?ad=1"
        ]
        
        for url in test_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy post-roll: {url}")
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, 'post-roll', f"Nieprawidłowy typ dla: {url}")
    
    def test_overlay_banner_classification(self):
        """Test rozpoznawania reklam overlay/banner"""
        test_urls = [
            "https://www.youtube.com/pagead/interaction/?ad_format=overlay",
            "https://www.youtube.com/pagead/adunit/banner?format=overlay",
            "https://www.youtube.com/api/stats/ads?ad_format=banner"
        ]
        
        for url in test_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy overlay: {url}")
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, 'overlay', f"Nieprawidłowy typ dla: {url}")
    
    def test_companion_ad_classification(self):
        """Test rozpoznawania reklam companion"""
        test_urls = [
            "https://www.youtube.com/pagead/adunit/companion?type=companion_ad",
            "https://www.youtube.com/api/stats/ads?ad_format=companion"
        ]
        
        for url in test_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy companion: {url}")
                ad_type, ad_name, is_skippable = result
                self.assertEqual(ad_type, 'companion', f"Nieprawidłowy typ dla: {url}")
    
    def test_regular_video_not_classified_as_ad(self):
        """Test że zwykłe wideo nie jest klasyfikowane jako reklama (brak fałszywych trafień)"""
        regular_video_urls = [
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?id=o-AB123&itag=22&source=youtube",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://r3.sn-4g5e6nzz.googlevideo.com/videoplayback?expire=123&ei=abc&ip=1.2.3.4&id=xyz&itag=18",
            "https://www.youtube.com/api/stats/qoe?docid=abc123&fmt=720p",
            "https://i.ytimg.com/vi/abc123/hqdefault.jpg",
            "https://www.youtube.com/get_video_info?video_id=abc123",
            "https://s.ytimg.com/yts/jsbin/player-vflset/en_US/base.js"
        ]
        
        for url in regular_video_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNone(result, f"Fałszywe trafienie - zwykłe wideo sklasyfikowane jako reklama: {url}")
    
    def test_ad_domain_blocking(self):
        """Test blokowania znanych domen reklamowych"""
        ad_domain_urls = [
            "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
            "https://doubleclick.net/ads/tracking",
            "https://googleadservices.com/pagead/conversion",
            "https://www.google-analytics.com/collect?aip=1",
            "https://innovid.com/ads/video",
            "https://ad.doubleclick.net/ddm/trackimp"
        ]
        
        for url in ad_domain_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano domeny reklamowej: {url}")
    
    def test_youtube_ad_paths(self):
        """Test rozpoznawania reklamowych ścieżek YouTube"""
        ad_path_urls = [
            "https://www.youtube.com/pagead/adview?client=ca-pub-123",
            "https://www.youtube.com/ptracking?event=start&ad_id=123",
            "https://www.youtube.com/_get_ads?video_id=abc",
            "https://www.youtube.com/api/stats/ads?docid=abc123",
            "https://www.youtube.com/pagead/conversion/?data=abc",
            "https://www.youtube.com/youtubei/v1/player/ad_break"
        ]
        
        for url in ad_path_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamowej ścieżki: {url}")
    
    def test_googlevideo_ad_patterns(self):
        """Test rozpoznawania wzorców reklamowych w domenach googlevideo"""
        googlevideo_ad_urls = [
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&ctier=L&id=abc",
            "https://r3.sn-4g5e6nzz.googlevideo.com/videoplayback?ad_type=video&adpodposition=0",
            "https://r12---sn-ab5sznez.googlevideo.com/videoplayback?ads_tag=1&oad=1",
            "https://redirector.googlevideo.com/videoplayback?adtagurl=http://example.com"
        ]
        
        for url in googlevideo_ad_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano reklamy w googlevideo: {url}")
    
    def test_url_normalization(self):
        """Test normalizacji URL (dekodowanie, parsowanie parametrów)"""
        encoded_url = "https://www.youtube.com/api/stats/ads?video_id=abc%20123&ad%5Ftype=preroll"
        base_url, params = self.classifier.normalize_url(encoded_url)
        
        self.assertIn('video_id', params)
        self.assertEqual(params['video_id'], 'abc 123')
        self.assertIn('ad_type', params)
        self.assertEqual(params['ad_type'], 'preroll')
    
    def test_heuristics_extraction(self):
        """Test wyciągania heurystyk z URL"""
        url = "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=2&ctier=L&ad_type=video&dur=30"
        base_url, params = self.classifier.normalize_url(url)
        heuristics = self.classifier.extract_heuristics(url, params)
        
        self.assertTrue(heuristics['has_oad_flag'])
        self.assertTrue(heuristics['has_ctier_l'])
        self.assertTrue(heuristics['has_ad_type'])
        self.assertEqual(heuristics['adpodposition'], 2)
        self.assertEqual(heuristics['duration'], 30)
    
    def test_mixed_content_urls(self):
        """Test URL-i z mieszaną zawartością (parametry reklam + wideo)"""
        # Te URL-e mają parametry reklamowe i powinny być blokowane
        mixed_urls_to_block = [
            "https://r5---sn-aigl6nls.googlevideo.com/videoplayback?id=video123&itag=22&oad=1&ctier=L",
            "https://www.youtube.com/get_video_info?video_id=abc&ad_type=preroll"
        ]
        
        for url in mixed_urls_to_block:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"URL z parametrami reklamowymi powinien być zablokowany: {url}")
    
    def test_edge_cases(self):
        """Test przypadków brzegowych"""
        edge_cases = [
            ("", None),  # Pusty URL
            (None, None),  # None URL
            ("invalid-url-without-protocol", None),  # Nieprawidłowy URL
            ("https://www.youtube.com/", None),  # Główna strona YouTube
        ]
        
        for url, expected in edge_cases:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                if expected is None:
                    self.assertIsNone(result, f"Powinno zwrócić None dla: {url}")
    
    def test_2024_2025_ad_patterns(self):
        """Test najnowszych wzorców reklamowych z 2024/2025"""
        modern_ad_urls = [
            "https://r15.sn-4g5e6nez.googlevideo.com/videoplayback?oad=1&adbreaktype=1",
            "https://www.youtube.com/youtubei/v1/player/ad_break?key=abc",
            "https://www.youtube.com/api/stats/ads_break?event=start",
            "https://www.youtube.com/ads_data_monitor?format=json",
            "https://r8---sn-h5q7knek.googlevideo.com/videoplayback?adtagurl=http://ad.example.com",
            "https://www.youtube.com/live_stats?adformat=overlay",
            "https://www.youtube.com/api/stats/delayplay?ad=1"
        ]
        
        for url in modern_ad_urls:
            with self.subTest(url=url):
                result = self.classifier.classify_ad(url)
                self.assertIsNotNone(result, f"Nie rozpoznano nowoczesnego wzorca reklamowego: {url}")


class TestAdSignaturesFile(unittest.TestCase):
    """Testy struktury pliku ad_signatures.json"""
    
    def test_signatures_file_exists(self):
        """Test czy plik sygnatur istnieje"""
        self.assertTrue(os.path.exists('ad_signatures.json'), "Plik ad_signatures.json nie istnieje")
    
    def test_signatures_file_valid_json(self):
        """Test czy plik sygnatur jest prawidłowym JSON"""
        with open('ad_signatures.json', 'r') as f:
            try:
                data = json.load(f)
                self.assertIsInstance(data, dict)
            except json.JSONDecodeError as e:
                self.fail(f"Plik ad_signatures.json nie jest prawidłowym JSON: {e}")
    
    def test_signatures_structure(self):
        """Test struktury pliku sygnatur"""
        with open('ad_signatures.json', 'r') as f:
            data = json.load(f)
        
        # Sprawdź wymagane sekcje
        self.assertIn('ad_patterns', data)
        self.assertIn('url_parameters', data)
        self.assertIn('domains', data)
        self.assertIn('path_patterns', data)
        
        # Sprawdź że ad_patterns zawiera wymagane pola
        for pattern in data['ad_patterns']:
            self.assertIn('name', pattern)
            self.assertIn('type', pattern)
            self.assertIn('skippable', pattern)
            self.assertIn('patterns', pattern)
            self.assertIsInstance(pattern['patterns'], list)


def run_tests():
    """Uruchom wszystkie testy"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Dodaj wszystkie testy
    suite.addTests(loader.loadTestsFromTestCase(TestAdClassifier))
    suite.addTests(loader.loadTestsFromTestCase(TestAdSignaturesFile))
    
    # Uruchom testy
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Wyświetl podsumowanie
    print("\n" + "=" * 70)
    print("PODSUMOWANIE TESTÓW")
    print("=" * 70)
    print(f"Uruchomiono testów: {result.testsRun}")
    print(f"Sukces: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Niepowodzenia: {len(result.failures)}")
    print(f"Błędy: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ Wszystkie testy przeszły pomyślnie!")
        return 0
    else:
        print("\n❌ Niektóre testy nie powiodły się!")
        return 1


if __name__ == '__main__':
    sys.exit(run_tests())
