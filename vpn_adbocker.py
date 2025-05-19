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

try:
    import pydivert  # dla Windows
    WINDOWS = True
except ImportError:
    WINDOWS = False
    try:
        import nfqueue  # dla Linux
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
    r'r[0-9]+---sn-[a-z0-9]+\.googlevideo\.com\/videoplayback\/.*\/ads'
]

# Skompilowane wyrażenia regularne dla lepszej wydajności
AD_PATTERNS = [re.compile(pattern) for pattern in YOUTUBE_AD_PATTERNS]

class Stats:
    """Statystyki blokowania"""
    def __init__(self):
        self.total_packets = 0
        self.blocked_packets = 0
        self.blocked_domains = defaultdict(int)
        self.clients = defaultdict(int)
        self.start_time = time.time()
    
    def add_packet(self, is_blocked=False, domain=None, client_ip=None):
        """Dodaj pakiet do statystyk"""
        self.total_packets += 1
        if is_blocked:
            self.blocked_packets += 1
            if domain:
                self.blocked_domains[domain] += 1
            if client_ip:
                self.clients[client_ip] += 1
    
    def print_stats(self):
        """Wyświetl statystyki"""
        elapsed = time.time() - self.start_time
        logger.info("=" * 60)
        logger.info("Statystyki blokowania reklam YouTube:")
        logger.info(f"Czas działania: {elapsed:.2f} sekund")
        logger.info(f"Łączna liczba pakietów: {self.total_packets}")
        logger.info(f"Zablokowane pakiety: {self.blocked_packets}")
        
        if self.blocked_domains:
            logger.info("Top 10 zablokowanych domen:")
            for domain, count in sorted(self.blocked_domains.items(), key=lambda x: x[1], reverse=True)[:10]:
                logger.info(f" - {domain}: {count} pakietów")
        
        if self.clients:
            logger.info("Top 5 klientów z zablokowanymi reklamami:")
            for ip, count in sorted(self.clients.items(), key=lambda x: x[1], reverse=True)[:5]:
                logger.info(f" - {ip}: {count} pakietów")
        
        if self.total_packets > 0:
            block_rate = (self.blocked_packets / self.total_packets) * 100
            logger.info(f"Procent zablokowanych pakietów: {block_rate:.2f}%")
        
        logger.info("=" * 60)

class YouTubeAdBlocker:
    """Główna klasa do blokowania reklam YouTube w ruchu VPN"""
    
    def __init__(self, interface, vpn_subnet=None, port=80, log_level=logging.INFO):
        self.interface = interface
        self.vpn_subnet = vpn_subnet
        self.port = port
        self.stats = Stats()
        self.running = False
        logger.setLevel(log_level)
        
        # Sprawdź dostępne metody przechwytywania pakietów
        if not WINDOWS and not LINUX_NFQUEUE:
            logger.error("Brak wymaganych bibliotek! Zainstaluj pydivert (Windows) lub nfqueue+scapy (Linux).")
            sys.exit(1)
    
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
                
                if url and self.is_ad_url(url):
                    logger.info(f"Blokowanie reklamy: {url} od {client_ip}")
                    self.stats.add_packet(is_blocked=True, domain=urllib.parse.urlparse(url).netloc, client_ip=client_ip)
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
                    
                    if url and self.is_ad_url(url):
                        logger.info(f"Blokowanie reklamy: {url} od {client_ip}")
                        self.stats.add_packet(is_blocked=True, domain=urllib.parse.urlparse(url).netloc, client_ip=client_ip)
                        # Odrzuć pakiet
                        payload.set_verdict(nfqueue.NF_DROP)
                        return
            
            # Przepuść pakiet
            self.stats.add_packet()
            payload.set_verdict(nfqueue.NF_ACCEPT)
            
        except Exception as e:
            logger.error(f"Błąd podczas przetwarzania pakietu: {e}")
            # W razie błędu przepuść pakiet
            payload.set_verdict(nfqueue.NF_ACCEPT)

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
        queue = nfqueue.queue()
        queue.open()
        queue.bind(1)  # Kolejka numer 1
        queue.set_callback(self.handle_packet_linux)
        queue.create_queue(1)
        
        logger.info("Blokowanie reklam YouTube aktywne. Naciśnij Ctrl+C, aby zakończyć.")
        
        try:
            # Uruchom pętlę główną
            while self.running:
                queue.try_run()
                
                # Okresowo wyświetlaj statystyki
                if self.stats.total_packets > 0 and self.stats.total_packets % 1000 == 0:
                    self.stats.print_stats()
                
                time.sleep(0.01)  # Mała pauza dla zmniejszenia obciążenia CPU
                
        except KeyboardInterrupt:
            logger.info("Otrzymano sygnał przerwania...")
        except Exception as e:
            logger.error(f"Nieoczekiwany błąd: {e}")
        finally:
            logger.info("Zatrzymywanie blokowania...")
            queue.unbind(1)
            queue.close()
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

