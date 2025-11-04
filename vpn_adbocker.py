#!/usr/bin/env python3
"""
YouTube VPN AdBlocker - blokowanie przekierowań reklamowych w ruchu VPN
Wykrywa i blokuje przekierowania na reklamy YouTube przez monitorowanie ruchu sieciowego.
"""

import os
import sys
import time
import signal
import logging
import argparse
import re
import socket
import struct
import threading
import subprocess
import json
from collections import defaultdict
import urllib.parse
from typing import Dict, Optional, Tuple, List

try:
    import pydivert  # dla Windows
    WINDOWS = True
except ImportError:
    WINDOWS = False
    try:
        from netfilterqueue import NetfilterQueue  # dla Linux - poprawna nazwa modułu
        from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw
        LINUX_NFQUEUE = True
    except ImportError:
        LINUX_NFQUEUE = False

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('youtube-vpn-adblock')

# Wzorce reklamowe YouTube do wykrycia w pakietach HTTP/HTTPS
YOUTUBE_AD_PATTERNS = [
    # Parametry URL używane przez YouTube dla reklam
    r'&ad_type=',
    r'&adformat=',
    r'&annotation_id=',
    r'&atype=',
    r'googlevideo.com/videoplayback.*&oad=',
    r'youtube.com/pagead/',
    r'youtube.com/ptracking',
    r'youtube.com/api/stats/ads',
    r'youtube-nocookie.com/api/stats/ads',
    # Adresy i nazwy serwerów reklamowych
    r'doubleclick.net',
    r'googlesyndication.com',
    r'googleadservices.com',
    r'.google-analytics.com',
    r'ads.youtube.com',
    # Specyficzne wzorce przekierowań
    r'ytv.svr.youtube.com/redirect\?',
    r'www.youtube.com/pagead/',
    r'www.youtube.com/ptracking',
    r'www.youtube.com/_get_ads',
    # Parametry w adresach videplayback
    r'videoplayback.*&ctier=L',
    r'videoplayback.*&rqs=',
    r'videoplayback.*&id=[0-9a-zA-Z_-]+\.[0-9]+\.[0-9]+\.[0-9]+',
    # Wzorce URL w wideo pre-rollowych
    r'redirector.googlevideo.com/videoplayback',
    r'r[0-9]+---sn-[a-z0-9]+\.googlevideo\.com\/videoplayback\/.*\/ads',
    
    # Nowe wzorce
    r'adservice\.google\.',
    r'pagead2\.googlesyndication\.com',
    r'youtube\.com\/api\/stats\/ads',
    r'youtube\.com\/pagead\/adview',
    r'youtube\.com\/get_midroll_',
    r'\.googlevideo\.com\/videogoodput',
    r'\.youtube\.com\/api\/stats\/qoe\?adformat',
    r'\.youtube\.com\/pagead\/interaction',
    r'innovid\.com',
    r'youtube\.com\/pagead\/conversion',
    r'youtube\.com\/pagead\/viewthroughconversion',
    r's\.ytimg\.com\/yts\/swfbin\/player-.*\/watch_as3\.swf',
    r'youtube\.com\/_get_ads',
    r'youtube\.com\/ptracking\?',
    r'youtube\.com\/get_video_info\?.*(&ad_type=|&adformat=)',
    r'youtube\.com\/api\/stats\/atr',
    r'ad\.doubleclick\.net',
    r'\.2mdn\.net',
    r'youtubei\.googleapis\.com\/youtubei\/v1\/player\/ad',
    r'\.googlevideo\.com\/ptracking\?',
    r'\.googlevideo\.com\/sodar\/',
    r'\.googlevideo\.com\/generate_204',
    r'manifest\.googlevideo\.com',
    r'googleads\.g\.doubleclick\.net',
    r'\.googlevideo\.com.*\/ad_break',
    r'\.googlevideo\.com.*&ctier=L',
    r'\.googlevideo\.com.*&oad',
    r'\.youtube\.com\/pcs\/activeview',
    r'\.youtube\.com\/pagead\/',
    r'r[0-9]+---sn-[a-z0-9]+-[a-z0-9]+\.googlevideo\.com',
    r'\.youtube-nocookie\.com\/api\/stats\/ads',
    r'\.youtube-nocookie\.com\/pagead\/',
    r'dynamicadplacement',
    
    # Najnowsze wzorce bloków reklamowych z 2025 roku
    r'r[0-9]+\.sn-[a-z0-9-]+\.googlevideo\.com',
    r'r[0-9]+---sn-[a-z0-9]{8}\.googlevideo\.com',
    r'r[0-9]+\.sn-[a-z0-9]+-[a-z0-9]{4}\.googlevideo\.com',
    r'\.googlevideo\.com\/videogoodput.*\/adunit\/',
    r'youtube\.com\/youtubei\/v1\/player\/ad_',
    r'youtube\.com\/api\/stats\/ads_break',
    r'youtube\.com\/api\/stats\/playback\/post_playback',
    r'youtube\.com\/ads_data_monitor',
    r'youtube\.com\/pagead\/adunit\/',
    r'youtube\.com\/live_stats\?.*adformat',
    r'youtube\.com\/api\/stats\/delayplay',
    r'youtube\.com\/pagead\/viewthroughconversion\/',
    r'googlevideo\.com.*\/ad_break\?',
    r'googlevideo\.com.*&adbreaktype=',
    r'googlevideo\.com.*&adtagurl=',
    r'googlevideo\.com.*&ad_type=',
    r'googlevideo\.com\/api\/ads\/',
    r'google-analytics\.com\/collect.*aip=',
    r'youtube\.com\/watch_fragments_ajax.*adunit',
    r'youtube\.com\/api\/stats\/qoe\?event=streamingstats.*adformat',
    r'youtube\.com\/pagead\/interaction\/\?ai=',
    r'\.googlevideo\.com\/videoplayback\/.*\/ads',
    r'googlevideo\.com\/videoplayback.*&adpodposition',
    r'youtube\.com\/get_midroll_info\?ei=',
    r'\.googlevideo\.com\/ptracking.*adurl',
    r'\.googlevideo\.com\/videoplayback.*&ads_tag='
]

# Skompilowane wyrażenia regularne dla lepszej wydajności
AD_PATTERNS = [re.compile(pattern) for pattern in YOUTUBE_AD_PATTERNS]

class AdClassifier:
    """Klasyfikator reklam YouTube z rozróżnieniem typów"""
    
    def __init__(self, signatures_file='ad_signatures.json'):
        """Inicjalizacja klasyfikatora z pliku sygnatur"""
        self.signatures = self._load_signatures(signatures_file)
        self.compiled_patterns = self._compile_patterns()
    
    def _load_signatures(self, signatures_file: str) -> Dict:
        """Wczytaj sygnatury reklam z pliku JSON"""
        try:
            # Sprawdź ścieżkę względem lokalizacji skryptu
            script_dir = os.path.dirname(os.path.abspath(__file__))
            full_path = os.path.join(script_dir, signatures_file)
            
            if os.path.exists(full_path):
                with open(full_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            elif os.path.exists(signatures_file):
                with open(signatures_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                logger.warning(f"Nie znaleziono pliku sygnatur {signatures_file}, używam domyślnych wzorców")
                return self._get_default_signatures()
        except Exception as e:
            logger.error(f"Błąd wczytywania sygnatur: {e}")
            return self._get_default_signatures()
    
    def _get_default_signatures(self) -> Dict:
        """Zwróć domyślne sygnatury gdy plik nie jest dostępny"""
        return {
            "ad_patterns": [
                {
                    "name": "pre_roll_skippable",
                    "type": "pre-roll",
                    "skippable": True,
                    "patterns": ["adpodposition=0", "preroll"],
                    "heuristics": {"has_oad_flag": True}
                }
            ],
            "url_parameters": {"ad_indicators": ["oad", "ad_type", "adformat"]},
            "domains": {"ad_servers": ["doubleclick.net", "googlesyndication.com"]},
            "path_patterns": {"ad_paths": ["/pagead/", "/ptracking"]}
        }
    
    def _compile_patterns(self) -> Dict:
        """Kompiluj wyrażenia regularne dla lepszej wydajności"""
        compiled = {
            '_ordered_patterns': []  # Zachowaj kolejność z pliku JSON
        }
        
        for pattern_data in self.signatures.get('ad_patterns', []):
            name = pattern_data['name']
            pattern_info = {
                'name': name,
                'type': pattern_data['type'],
                'skippable': pattern_data['skippable'],
                'patterns': [re.compile(p, re.IGNORECASE) for p in pattern_data.get('patterns', [])],
                'heuristics': pattern_data.get('heuristics', {})
            }
            compiled[name] = pattern_info
            compiled['_ordered_patterns'].append(name)
        
        # Kompiluj wzorce domen
        if 'domains' in self.signatures:
            compiled['domain_patterns'] = [
                re.compile(domain, re.IGNORECASE) 
                for domain in self.signatures['domains'].get('googlevideo_ad_patterns', [])
            ]
        
        # Kompiluj wzorce ścieżek
        if 'path_patterns' in self.signatures:
            compiled['path_patterns'] = [
                re.compile(path, re.IGNORECASE) 
                for path in self.signatures['path_patterns'].get('videoplayback_ad_indicators', [])
            ]
        
        return compiled
    
    def normalize_url(self, url: str) -> Tuple[str, Dict[str, str]]:
        """
        Normalizuj URL - dekoduj i wyciągnij parametry
        
        Returns:
            Tuple: (base_url, parameters_dict)
        """
        try:
            # Dekoduj URL
            decoded_url = urllib.parse.unquote(url)
            
            # Parsuj URL
            parsed = urllib.parse.urlparse(decoded_url)
            
            # Wyciągnij parametry
            params = urllib.parse.parse_qs(parsed.query)
            
            # Spłaszcz parametry (weź pierwszą wartość z każdej listy)
            flat_params = {k: v[0] if isinstance(v, list) and v else v for k, v in params.items()}
            
            # Zwróć bazowy URL bez parametrów i słownik parametrów
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else f"{parsed.netloc}{parsed.path}"
            
            return base_url, flat_params
        except Exception as e:
            logger.debug(f"Błąd normalizacji URL: {e}")
            return url, {}
    
    def extract_heuristics(self, url: str, params: Dict[str, str]) -> Dict:
        """Wyciągnij heurystyki z URL i parametrów"""
        heuristics = {
            'has_oad_flag': 'oad' in params or 'oad=' in url.lower(),
            'has_adgoogleid': 'adgoogleid' in params or 'googleadid' in params,
            'has_ctier_l': params.get('ctier', '').upper() == 'L',
            'has_ad_type': 'ad_type' in params or 'adtype' in params,
            'adpodposition': int(params.get('adpodposition', -1)) if params.get('adpodposition', '').isdigit() else -1,
            'duration': int(params.get('dur', 0)) if params.get('dur', '').replace('.', '').isdigit() else 0
        }
        
        return heuristics
    
    def classify_ad(self, url: str) -> Optional[Tuple[str, str, bool]]:
        """
        Klasyfikuj żądanie reklamowe
        
        Returns:
            Tuple: (ad_type, ad_name, is_skippable) or None if not an ad
            ad_type: 'pre-roll', 'mid-roll', 'post-roll', 'overlay', 'companion'
        """
        if not url:
            return None
        
        # Normalizuj URL
        base_url, params = self.normalize_url(url)
        full_url = url.lower()
        
        # Sprawdź czy to w ogóle reklama
        if not self._is_ad_request(full_url, params):
            return None
        
        # Wyciągnij heurystyki
        heuristics = self.extract_heuristics(url, params)
        
        # Klasyfikuj według wzorców (użyj kolejności z pliku JSON)
        for name in self.compiled_patterns.get('_ordered_patterns', []):
            pattern_data = self.compiled_patterns[name]
            
            # Sprawdź wzorce
            match_found = False
            for pattern in pattern_data['patterns']:
                if pattern.search(full_url):
                    match_found = True
                    break
            
            if not match_found:
                continue
            
            # Sprawdź heurystyki (jeśli są wymagane)
            required_heuristics = pattern_data.get('heuristics', {})
            heuristics_match = True
            
            # Tylko sprawdzaj heurystyki jeśli są zdefiniowane
            if required_heuristics:
                if 'has_oad_flag' in required_heuristics:
                    if required_heuristics['has_oad_flag'] and not heuristics['has_oad_flag']:
                        heuristics_match = False
                
                if 'has_adgoogleid' in required_heuristics:
                    if required_heuristics['has_adgoogleid'] and not heuristics['has_adgoogleid']:
                        heuristics_match = False
            
            if heuristics_match:
                return (pattern_data['type'], name, pattern_data['skippable'])
        
        # Jeśli nie znaleziono konkretnego wzorca, ale to reklama, klasyfikuj heurycznie
        if heuristics['adpodposition'] >= 0:
            if heuristics['adpodposition'] == 0:
                return ('pre-roll', 'pre_roll_generic', True)
            else:
                return ('mid-roll', 'mid_roll_generic', True)
        
        # Domyślna klasyfikacja
        return ('unknown', 'unknown_ad', True)
    
    def _is_ad_request(self, url: str, params: Dict[str, str]) -> bool:
        """Sprawdź czy żądanie jest reklamą"""
        # Sprawdź parametry URL
        ad_indicators = self.signatures.get('url_parameters', {}).get('ad_indicators', [])
        for indicator in ad_indicators:
            if indicator in params or f"{indicator}=" in url:
                return True
        
        # Sprawdź domeny
        ad_servers = self.signatures.get('domains', {}).get('ad_servers', [])
        for server in ad_servers:
            if server in url:
                return True
        
        # Sprawdź wzorce domen googlevideo
        for pattern in self.compiled_patterns.get('domain_patterns', []):
            if pattern.search(url):
                # Sprawdź dodatkowe wskaźniki dla googlevideo
                if any(ind in url for ind in ['oad=', 'ctier=l', 'ad_type=', 'adpodposition=']):
                    return True
        
        # Sprawdź ścieżki
        ad_paths = self.signatures.get('path_patterns', {}).get('ad_paths', [])
        for path in ad_paths:
            if path.lower() in url:
                return True
        
        # Sprawdź wzorce videoplayback
        for pattern in self.compiled_patterns.get('path_patterns', []):
            if pattern.search(url):
                return True
        
        return False

class Stats:
    """Statystyki blokowania z rozróżnieniem typów reklam"""
    def __init__(self):
        self.total_packets = 0
        self.blocked_packets = 0
        self.blocked_domains = defaultdict(int)
        self.clients = defaultdict(int)
        self.start_time = time.time()
        
        # Statystyki według typu reklamy
        self.blocked_preroll = 0
        self.blocked_midroll = 0
        self.blocked_postroll = 0
        self.blocked_overlay = 0
        self.blocked_companion = 0
        self.blocked_unknown = 0
        
        # Statystyki skippable/non-skippable
        self.blocked_skippable = 0
        self.blocked_nonskippable = 0
        
        # Szczegółowe statystyki według nazwy wzorca
        self.blocked_by_pattern = defaultdict(int)
    
    def add_packet(self, is_blocked=False, domain=None, client_ip=None, ad_type=None, ad_name=None, is_skippable=None):
        """Dodaj pakiet do statystyk"""
        self.total_packets += 1
        if is_blocked:
            self.blocked_packets += 1
            if domain:
                self.blocked_domains[domain] += 1
            if client_ip:
                self.clients[client_ip] += 1
            
            # Statystyki według typu reklamy
            if ad_type:
                if ad_type == 'pre-roll':
                    self.blocked_preroll += 1
                elif ad_type == 'mid-roll':
                    self.blocked_midroll += 1
                elif ad_type == 'post-roll':
                    self.blocked_postroll += 1
                elif ad_type == 'overlay':
                    self.blocked_overlay += 1
                elif ad_type == 'companion':
                    self.blocked_companion += 1
                else:
                    self.blocked_unknown += 1
            else:
                self.blocked_unknown += 1
            
            # Statystyki skippable/non-skippable
            if is_skippable is not None:
                if is_skippable:
                    self.blocked_skippable += 1
                else:
                    self.blocked_nonskippable += 1
            
            # Statystyki według wzorca
            if ad_name:
                self.blocked_by_pattern[ad_name] += 1
    
    def print_stats(self):
        """Wyświetl statystyki"""
        elapsed = time.time() - self.start_time
        logger.info("=" * 70)
        logger.info("Statystyki blokowania reklam YouTube:")
        logger.info(f"Czas działania: {elapsed:.2f} sekund")
        logger.info(f"Łączna liczba pakietów: {self.total_packets}")
        logger.info(f"Zablokowane pakiety: {self.blocked_packets}")
        
        # Statystyki według typu reklamy
        if self.blocked_packets > 0:
            logger.info("\nZablokowane reklamy według typu:")
            logger.info(f" - Pre-roll:   {self.blocked_preroll:5d} ({self.blocked_preroll/self.blocked_packets*100:5.1f}%)")
            logger.info(f" - Mid-roll:   {self.blocked_midroll:5d} ({self.blocked_midroll/self.blocked_packets*100:5.1f}%)")
            logger.info(f" - Post-roll:  {self.blocked_postroll:5d} ({self.blocked_postroll/self.blocked_packets*100:5.1f}%)")
            logger.info(f" - Overlay:    {self.blocked_overlay:5d} ({self.blocked_overlay/self.blocked_packets*100:5.1f}%)")
            logger.info(f" - Companion:  {self.blocked_companion:5d} ({self.blocked_companion/self.blocked_packets*100:5.1f}%)")
            logger.info(f" - Unknown:    {self.blocked_unknown:5d} ({self.blocked_unknown/self.blocked_packets*100:5.1f}%)")
            
            logger.info("\nZablokowane reklamy według właściwości:")
            logger.info(f" - Skippable:     {self.blocked_skippable:5d} ({self.blocked_skippable/self.blocked_packets*100:5.1f}%)")
            logger.info(f" - Non-skippable: {self.blocked_nonskippable:5d} ({self.blocked_nonskippable/self.blocked_packets*100:5.1f}%)")
        
        if self.blocked_domains:
            logger.info("\nTop 10 zablokowanych domen:")
            for domain, count in sorted(self.blocked_domains.items(), key=lambda x: x[1], reverse=True)[:10]:
                logger.info(f" - {domain}: {count} pakietów")
        
        if self.blocked_by_pattern:
            logger.info("\nTop 10 wzorców reklamowych:")
            for pattern, count in sorted(self.blocked_by_pattern.items(), key=lambda x: x[1], reverse=True)[:10]:
                logger.info(f" - {pattern}: {count} pakietów")
        
        if self.clients:
            logger.info("\nTop 5 klientów z zablokowanymi reklamami:")
            for ip, count in sorted(self.clients.items(), key=lambda x: x[1], reverse=True)[:5]:
                logger.info(f" - {ip}: {count} pakietów")
        
        if self.total_packets > 0:
            block_rate = (self.blocked_packets / self.total_packets) * 100
            logger.info(f"\nProcent zablokowanych pakietów: {block_rate:.2f}%")
        
        logger.info("=" * 70)

class YouTubeAdBlocker:
    """Główna klasa do blokowania reklam YouTube w ruchu VPN"""
    
    def __init__(self, interface, vpn_subnet=None, port=80, log_level=logging.INFO, signatures_file='ad_signatures.json'):
        self.interface = interface
        self.vpn_subnet = vpn_subnet
        self.port = port
        self.stats = Stats()
        self.running = False
        self.classifier = AdClassifier(signatures_file)
        logger.setLevel(log_level)
        
        # Sprawdź dostępne metody przechwytywania pakietów
        if not WINDOWS and not LINUX_NFQUEUE:
            logger.error("Brak wymaganych bibliotek! Zainstaluj pydivert (Windows) lub nfqueue+scapy (Linux).")
            sys.exit(1)
        
        logger.info(f"Załadowano klasyfikator reklam z {len(self.classifier.compiled_patterns)} wzorcami")
    
    def is_ad_url(self, url):
        """Sprawdź, czy URL jest reklamą YouTube"""
        if not url:
            return False
        
        # Zdekoduj URL
        try:
            decoded_url = urllib.parse.unquote(url)
        except:
            decoded_url = url
        
        # Sprawdź wzorce reklamowe
        for pattern in AD_PATTERNS:
            if pattern.search(decoded_url):
                return True
        
        return False
    
    def extract_host_from_packet(self, packet_data):
        """Wyciągnij nazwę hosta z pakietu HTTP/HTTPS"""
        try:
            # Próba znalezienia nagłówka Host: w pakiecie HTTP
            if b'Host: ' in packet_data:
                host_start = packet_data.find(b'Host: ') + 6
                host_end = packet_data.find(b'\r\n', host_start)
                if host_end > host_start:
                    return packet_data[host_start:host_end].decode('utf-8', errors='ignore')
            
            # Próba znalezienia URL w żądaniu HTTP
            http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ']
            for method in http_methods:
                if method in packet_data:
                    start = packet_data.find(method) + len(method)
                    end = packet_data.find(b' HTTP/', start)
                    if end > start:
                        url = packet_data[start:end].decode('utf-8', errors='ignore')
                        parsed = urllib.parse.urlparse(url)
                        if parsed.netloc:
                            return parsed.netloc
                        elif url.startswith('/'):
                            # Względny URL, sprawdź nagłówek Host
                            return self.extract_host_from_packet(packet_data)
            
            # Dla HTTPS sprawdź SNI (Server Name Indication)
            # Uproszczona implementacja, pełna wymagałaby parsowania protokołu TLS
            if b'\x16\x03' in packet_data:  # Handshake TLS
                sni_pos = packet_data.find(b'\x00\x00')
                if sni_pos > 0 and sni_pos + 5 < len(packet_data):
                    sni_len = packet_data[sni_pos + 3]
                    if sni_pos + 5 + sni_len <= len(packet_data):
                        return packet_data[sni_pos + 5:sni_pos + 5 + sni_len].decode('utf-8', errors='ignore')
        
        except Exception as e:
            logger.debug(f"Błąd podczas wyciągania hosta: {e}")
        
        return None

    def extract_url_from_packet(self, packet_data):
        """Wyciągnij URL z pakietu HTTP"""
        try:
            http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ']
            for method in http_methods:
                if method in packet_data:
                    start = packet_data.find(method) + len(method)
                    end = packet_data.find(b' HTTP/', start)
                    if end > start:
                        url = packet_data[start:end].decode('utf-8', errors='ignore')
                        host = self.extract_host_from_packet(packet_data)
                        if host and not url.startswith('http'):
                            if url.startswith('/'):
                                url = f"http://{host}{url}"
                            else:
                                url = f"http://{host}/{url}"
                        return url
        except Exception as e:
            logger.debug(f"Błąd podczas wyciągania URL: {e}")
        
        return None

    def handle_packet_windows(self, packet):
        """Obsługa pakietu w Windows używając pydivert"""
        try:
            # Filtruj tylko ruch HTTP/HTTPS
            if (packet.tcp and (packet.tcp.dst_port == 80 or packet.tcp.dst_port == 443)) or \
               (packet.tcp and (packet.tcp.src_port == 80 or packet.tcp.src_port == 443)):
                
                packet_data = bytes(packet.payload)
                client_ip = packet.src_addr
                url = self.extract_url_from_packet(packet_data)
                
                if url:
                    # Użyj nowego klasyfikatora
                    classification = self.classifier.classify_ad(url)
                    
                    if classification:
                        ad_type, ad_name, is_skippable = classification
                        skip_type = "skippable" if is_skippable else "non-skippable"
                        logger.info(f"🚫 Blokowanie reklamy [{ad_type}, {skip_type}]: {url[:100]}... od {client_ip}")
                        
                        domain = urllib.parse.urlparse(url).netloc
                        self.stats.add_packet(
                            is_blocked=True, 
                            domain=domain, 
                            client_ip=client_ip,
                            ad_type=ad_type,
                            ad_name=ad_name,
                            is_skippable=is_skippable
                        )
                        # Nie kontynuuj z tym pakietem (zablokuj)
                        return None
                
                self.stats.add_packet()
            
            # Przepuść pakiet
            return packet
            
        except Exception as e:
            logger.error(f"Błąd podczas przetwarzania pakietu: {e}")
            # W razie błędu przepuść pakiet
            return packet

    def handle_packet_linux(self, i, payload):
        """Obsługa pakietu w Linux używając nfqueue"""
        try:
            data = payload.get_data()
            packet = IP(data)
            
            # Filtruj tylko ruch HTTP/HTTPS
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                if (tcp_layer.dport == 80 or tcp_layer.dport == 443 or 
                    tcp_layer.sport == 80 or tcp_layer.sport == 443) and packet.haslayer(Raw):
                    
                    packet_data = bytes(packet.getlayer(Raw))
                    client_ip = packet[IP].src
                    url = self.extract_url_from_packet(packet_data)
                    
                    if url:
                        # Użyj nowego klasyfikatora
                        classification = self.classifier.classify_ad(url)
                        
                        if classification:
                            ad_type, ad_name, is_skippable = classification
                            skip_type = "skippable" if is_skippable else "non-skippable"
                            logger.info(f"🚫 Blokowanie reklamy [{ad_type}, {skip_type}]: {url[:100]}... od {client_ip}")
                            
                            domain = urllib.parse.urlparse(url).netloc
                            self.stats.add_packet(
                                is_blocked=True, 
                                domain=domain, 
                                client_ip=client_ip,
                                ad_type=ad_type,
                                ad_name=ad_name,
                                is_skippable=is_skippable
                            )
                            # Odrzuć pakiet
                            payload.drop()
                            return
            
            # Przepuść pakiet
            self.stats.add_packet()
            payload.accept()
            
        except Exception as e:
            logger.error(f"Błąd podczas przetwarzania pakietu: {e}")
            # W razie błędu przepuść pakiet
            payload.accept()

    def setup_iptables_rules(self):
        """Konfiguruje reguły iptables do przechwytywania pakietów"""
        if not LINUX_NFQUEUE:
            return
        
        logger.info("Konfiguracja iptables...")
        
        # Zapisz istniejące reguły, aby można je było przywrócić
        try:
            subprocess.run(['iptables-save', '>', '/tmp/iptables-backup.rules'], shell=True)
        except Exception as e:
            logger.error(f"Nie udało się zapisać istniejących reguł iptables: {e}")
        
        # Dodaj reguły do przekierowywania pakietów do nfqueue
        cmds = [
            # Przekieruj ruch HTTP do nfqueue
            f"iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1",
            f"iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1",
            # Przekieruj ruch HTTPS do nfqueue
            f"iptables -A FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 1",
            f"iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1",
        ]
        
        if self.vpn_subnet:
            # Dodatkowe reguły dla konkretnej podsieci VPN
            cmds.extend([
                f"iptables -A FORWARD -s {self.vpn_subnet} -p tcp --dport 80 -j NFQUEUE --queue-num 1",
                f"iptables -A FORWARD -s {self.vpn_subnet} -p tcp --dport 443 -j NFQUEUE --queue-num 1"
            ])
        
        for cmd in cmds:
            try:
                subprocess.run(cmd, shell=True, check=True)
                logger.debug(f"Wykonano: {cmd}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Błąd podczas konfiguracji iptables: {e}")
    
    def cleanup_iptables_rules(self):
        """Usuwa reguły iptables po zatrzymaniu programu"""
        if not LINUX_NFQUEUE:
            return
        
        logger.info("Czyszczenie reguł iptables...")
        
        cmds = [
            "iptables -D FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1",
            "iptables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1",
            "iptables -D FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 1",
            "iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1"
        ]
        
        if self.vpn_subnet:
            cmds.extend([
                f"iptables -D FORWARD -s {self.vpn_subnet} -p tcp --dport 80 -j NFQUEUE --queue-num 1",
                f"iptables -D FORWARD -s {self.vpn_subnet} -p tcp --dport 443 -j NFQUEUE --queue-num 1"
            ])
        
        for cmd in cmds:
            try:
                subprocess.run(cmd, shell=True)
                logger.debug(f"Wykonano: {cmd}")
            except Exception as e:
                logger.error(f"Błąd podczas czyszczenia iptables: {e}")
        
        # Przywróć zapisane reguły
        try:
            if os.path.exists('/tmp/iptables-backup.rules'):
                subprocess.run('iptables-restore < /tmp/iptables-backup.rules', shell=True)
                os.remove('/tmp/iptables-backup.rules')
        except Exception as e:
            logger.error(f"Nie udało się przywrócić reguł iptables: {e}")

    def start_windows(self):
        """Uruchom blokowanie w systemie Windows"""
        logger.info(f"Uruchamianie blokady reklam YouTube na interfejsie {self.interface}...")
        
        # Filtr pakietów
        filter_string = f"(tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 80 or tcp.SrcPort == 443)"
        if self.interface:
            filter_string += f" and ifname == '{self.interface}'"
        
        logger.info(f"Filtr: {filter_string}")
        
        with pydivert.WinDivert(filter_string) as w:
            logger.info("Blokowanie reklam YouTube aktywne. Naciśnij Ctrl+C, aby zakończyć.")
            
            try:
                while self.running:
                    # Pobierz pakiet
                    packet = w.recv()
                    
                    # Przetwórz pakiet
                    result_packet = self.handle_packet_windows(packet)
                    
                    # Jeśli pakiet nie został zablokowany, przepuść go
                    if result_packet:
                        w.send(result_packet)
                    
                    # Okresowo wyświetlaj statystyki
                    if self.stats.total_packets % 1000 == 0:
                        self.stats.print_stats()
            
            except KeyboardInterrupt:
                logger.info("Otrzymano sygnał przerwania...")
            except Exception as e:
                logger.error(f"Nieoczekiwany błąd: {e}")
            finally:
                logger.info("Zatrzymywanie blokowania...")

    def start_linux(self):
        """Uruchom blokowanie w systemie Linux"""
        logger.info(f"Uruchamianie blokady reklam YouTube w systemie Linux...")
        
        # Konfiguracja iptables
        self.setup_iptables_rules()
        
        # Utwórz i skonfiguruj kolejkę pakietów
        queue = NetfilterQueue()
        queue.bind(1, self.handle_packet_linux)  # Kolejka numer 1
        
        logger.info("Blokowanie reklam YouTube aktywne. Naciśnij Ctrl+C, aby zakończyć.")
        
        try:
            # Uruchom pętlę główną
            queue.run()
                
        except KeyboardInterrupt:
            logger.info("Otrzymano sygnał przerwania...")
        except Exception as e:
            logger.error(f"Nieoczekiwany błąd: {e}")
        finally:
            logger.info("Zatrzymywanie blokowania...")
            queue.unbind()
            self.cleanup_iptables_rules()

    def start(self):
        """Uruchom blokowanie reklam YouTube"""
        self.running = True
        
        # Obsługa sygnału SIGUSR1 do wyświetlania statystyk
        def print_stats_handler(signum, frame):
            self.stats.print_stats()
        
        signal.signal(signal.SIGUSR1, print_stats_handler)
        logger.info(f"PID: {os.getpid()} - Możesz wysłać sygnał SIGUSR1, aby wyświetlić statystyki")
        
        if WINDOWS:
            self.start_windows()
        elif LINUX_NFQUEUE:
            self.start_linux()
        else:
            logger.error("Brak dostępnej metody przechwytywania pakietów!")
            sys.exit(1)
        
        # Wyświetl końcowe statystyki
        self.stats.print_stats()

def detect_openvpn_interfaces():
    """Wykryj interfejsy OpenVPN i ich adresy IP"""
    interfaces = []
    try:
        if sys.platform == 'win32':
            # Windows - użyj ipconfig
            output = subprocess.check_output(['ipconfig'], text=True)
            adapter = None
            for line in output.split('\n'):
                if 'TAP-Windows Adapter' in line or 'OpenVPN' in line:
                    adapter = line.strip(':')
                elif adapter and 'IPv4 Address' in line:
                    ip = line.split(':')[-1].strip()
                    interfaces.append((adapter, ip))
                    adapter = None
        else:
            # Linux/Mac - użyj ifconfig
            output = subprocess.check_output(['ifconfig'], universal_newlines=True)
            current_interface = None
            for line in output.split('\n'):
                if line.startswith(('tun', 'tap')):
                    current_interface = line.split(':')[0].strip()
                elif current_interface and 'inet ' in line:
                    ip_address = line.split('inet ')[1].split(' ')[0].strip()
                    interfaces.append((current_interface, ip_address))
                    current_interface = None
    except Exception as e:
        logger.error(f"Błąd podczas wykrywania interfejsów OpenVPN: {e}")
    
    return interfaces

def detect_vpn_subnet():
    """Wykryj podsieć VPN"""
    try:
        interfaces = detect_openvpn_interfaces()
        if interfaces:
            for name, ip in interfaces:
                # Typowe podsieci dla OpenVPN to /24
                subnet = ip.rsplit('.', 1)[0] + '.0/24'
                logger.info(f"Wykryto podsieć VPN: {subnet} na interfejsie {name}")
                return subnet
    except Exception as e:
        logger.error(f"Błąd podczas wykrywania podsieci VPN: {e}")
    
    return None

def main():
    """Funkcja główna"""
    parser = argparse.ArgumentParser(description='Blokowanie reklam YouTube w ruchu VPN')
    parser.add_argument('--interface', help='Nazwa interfejsu sieciowego (np. tun0)')
    parser.add_argument('--subnet', help='Podsieć VPN (np. 10.8.0.0/24)')
    parser.add_argument('--port', type=int, default=80, help='Port HTTP (domyślnie 80)')
    parser.add_argument('--log', default='info', choices=['debug', 'info', 'warning', 'error'], 
                        help='Poziom logowania (domyślnie: info)')
    
    args = parser.parse_args()
    
    # Automatyczne wykrywanie, jeśli nie podano parametrów
    if not args.interface:
        vpn_interfaces = detect_openvpn_interfaces()
        if vpn_interfaces:
            args.interface = vpn_interfaces[0][0]
            logger.info(f"Wykryto interfejs OpenVPN: {args.interface}")
        else:
            logger.warning("Nie wykryto interfejsów OpenVPN! Nasłuchiwanie na wszystkich interfejsach.")
    
    if not args.subnet:
        args.subnet = detect_vpn_subnet()
    
    # Ustawienie poziomu logowania
    log_level = getattr(logging, args.log.upper())
    
    # Sprawdź, czy skrypt jest uruchamiany jako root (wymagane dla nfqueue i iptables)
    if sys.platform != 'win32' and os.geteuid() != 0:
        logger.error("Ten skrypt wymaga uprawnień administratora. Uruchom jako root (sudo).")
        sys.exit(1)
    
    try:
        # Uruchom bloker
        blocker = YouTubeAdBlocker(
            interface=args.interface,
            vpn_subnet=args.subnet,
            port=args.port,
            log_level=log_level
        )
        blocker.start()
    except KeyboardInterrupt:
        logger.info("Program przerwany przez użytkownika")
    except Exception as e:
        logger.error(f"Nieoczekiwany błąd: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main() 
