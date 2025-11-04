#!/usr/bin/env python3
import socket
import time
import threading
from dnslib import DNSRecord, RR, QTYPE, A, DNSHeader, DNSQuestion
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import argparse
import re
import logging
import sys
import os
import subprocess
import ipaddress
import traceback
import signal
import json

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('youtube-ad-blocker')

# Lista domen reklamowych YouTube i Google
AD_DOMAINS = [
    r'.*\.doubleclick\.net',
    r'.*\.googlesyndication\.com',
    r'.*\.googleadservices\.com',
    r'.*\.google-analytics\.com',
    r'.*\.googletagmanager\.com',
    r'.*\.googletagservices\.com',
    r'.*ads.*\.com',
    r'.*ad.*\.youtube\.com',
    r'.*\.youtube\.com\/pagead\/',
    r'.*\.youtube\.com\/ptracking',
    r'.*\.youtube\.com\/_get_ads',
    r'.*\.youtube\.com\/api\/stats\/ads',
    r'.*\.youtube\.com\/get_video_info.*(\&|\?)ad',
    r'.*\.youtube\.com\/pagead\/',
    r'.*\.youtube\.com\/ptracking',
    r'.*\.youtube\.com\/get_midroll_',
    r'.*\.youtube\.com\/api\/stats\/ads',
    r'.*\.youtube\.com\/watch_popup\?.*(\&|\?)ad',
    r'.*\.googlevideo\.com\/ptracking',
    r'.*\.googlevideo\.com\/videogoodput',
    r'r[0-9]+---sn-[a-z0-9]+\.googlevideo\.com',
    r'.*\.youtube-nocookie\.com\/gen_204\?',
    r'r[0-9]+-+sn-.*.googlevideo.com',
    r'.*pixel\..*',
    r'.*\.2mdn\.net',
    r'.*\.adsafeprotected\.com',
    r'.*\.serving-sys\.com',
    r'.*\.admob\..*',
    # Nowe domeny z 2024/2025
    r'.*\.innovid\.com',
    r'.*adservice\.google\..*',
    r'.*pagead2\.googlesyndication\.com',
    r'r[0-9]+\.sn-[a-z0-9-]+\.googlevideo\.com',
    r'r[0-9]+---sn-[a-z0-9]{8}\.googlevideo\.com',
    r'r[0-9]+\.sn-[a-z0-9]+-[a-z0-9]{4}\.googlevideo\.com',
    r'redirector\.googlevideo\.com'
]

def load_ad_domains_from_signatures():
    """Wczytaj domeny reklamowe z pliku ad_signatures.json"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        signatures_path = os.path.join(script_dir, 'ad_signatures.json')
        
        if os.path.exists(signatures_path):
            with open(signatures_path, 'r', encoding='utf-8') as f:
                signatures = json.load(f)
                
            # Dodaj domeny z pliku sygnatur
            additional_domains = []
            if 'domains' in signatures:
                for server in signatures['domains'].get('ad_servers', []):
                    additional_domains.append(f".*{re.escape(server)}")
                
                for pattern in signatures['domains'].get('googlevideo_ad_patterns', []):
                    additional_domains.append(pattern)
            
            logger.info(f"Załadowano {len(additional_domains)} dodatkowych domen z ad_signatures.json")
            return additional_domains
    except Exception as e:
        logger.warning(f"Nie udało się załadować domen z ad_signatures.json: {e}")
    
    return []

# Dodaj domeny z pliku sygnatur
AD_DOMAINS.extend(load_ad_domains_from_signatures())

# Kompilacja wyrażeń regularnych dla szybszego dopasowania
AD_PATTERNS = [re.compile(pattern) for pattern in AD_DOMAINS]

def print_packet_hex(data):
    """Wyświetla pakiet w formacie szesnastkowym dla debugowania"""
    hex_str = ' '.join('{:02x}'.format(b) for b in data)
    logger.debug(f"Pakiet HEX: {hex_str}")

def test_dns_connectivity():
    """Sprawdza, czy serwer może wysyłać/odbierać zapytania DNS"""
    try:
        logger.info("Testowanie łączności DNS...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        
        # Utwórz proste zapytanie DNS dla google.com
        q = DNSRecord.question("google.com")
        sock.sendto(q.pack(), ("8.8.8.8", 53))
        data, _ = sock.recvfrom(8192)
        sock.close()
        
        # Parsowanie odpowiedzi
        response = DNSRecord.parse(data)
        logger.info(f"Test DNS udany! Odpowiedź: {response}")
        return True
    except Exception as e:
        logger.error(f"Test DNS nieudany: {e}")
        logger.error(traceback.format_exc())
        return False

def get_openvpn_interfaces():
    """Wykryj interfejsy OpenVPN i ich adresy IP."""
    interfaces = []
    try:
        # Uruchom ifconfig, aby znaleźć wszystkie interfejsy sieciowe
        output = subprocess.check_output(['ifconfig'], universal_newlines=True)
        
        # Szukaj interfejsów tun lub tap (używanych przez OpenVPN)
        lines = output.split('\n')
        current_interface = None
        
        for line in lines:
            if line.startswith(('tun', 'tap')):
                current_interface = line.split(':')[0].strip()
            elif current_interface and 'inet ' in line:
                # Wyciągnij adres IP
                ip_address = line.split('inet ')[1].split(' ')[0].strip()
                interfaces.append((current_interface, ip_address))
                current_interface = None
                
        if not interfaces:
            logger.warning("Nie znaleziono interfejsów OpenVPN (tun/tap).")
    except Exception as e:
        logger.error(f"Błąd podczas wykrywania interfejsów OpenVPN: {e}")
    
    return interfaces

def check_dns_settings_in_openvpn():
    """Sprawdza konfigurację OpenVPN pod kątem ustawień DNS"""
    try:
        # Szukamy w typowych lokalizacjach plików konfiguracyjnych OpenVPN
        config_locations = [
            '/etc/openvpn',
            '/etc/openvpn/server',
            '/usr/local/etc/openvpn',
            os.path.expanduser('~/.openvpn')
        ]
        
        dns_config_found = False
        
        for location in config_locations:
            if os.path.exists(location):
                for file in os.listdir(location):
                    if file.endswith('.conf') or file.endswith('.ovpn'):
                        file_path = os.path.join(location, file)
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if 'dhcp-option DNS' in content:
                                dns_config_found = True
                                logger.info(f"Znaleziono konfigurację DNS w {file_path}")
                                # Sprawdź, czy adres IP naszego serwera jest w konfiguracji
                                for line in content.split('\n'):
                                    if 'dhcp-option DNS' in line:
                                        logger.info(f"  Ustawienie DNS: {line.strip()}")
        
        if not dns_config_found:
            logger.warning("Nie znaleziono ustawień DNS w plikach konfiguracyjnych OpenVPN!")
            logger.warning("Dodaj 'push \"dhcp-option DNS <IP_SERWERA>\"' do pliku konfiguracyjnego OpenVPN")
    except Exception as e:
        logger.error(f"Błąd podczas sprawdzania konfiguracji OpenVPN: {e}")

class PacketCapturingDNSHandler(DNSHandler):
    """Własny handler DNS z dodatkowym logowaniem"""
    def handle(self):
        try:
            data = self.request[0]
            logger.debug(f"Odebrano pakiet od {self.client_address[0]}, długość: {len(data)} bajtów")
            if logger.level <= logging.DEBUG:
                print_packet_hex(data)
            
            # Spróbuj sparsować jako pakiet DNS
            try:
                request = DNSRecord.parse(data)
                logger.debug(f"Zapytanie DNS: {request}")
            except Exception as e:
                logger.error(f"Nie udało się sparsować pakietu DNS: {e}")
            
            # Standardowe przetwarzanie zapytania
            return super().handle()
        except Exception as e:
            logger.error(f"Błąd w obsłudze pakietu: {e}")
            logger.error(traceback.format_exc())

class AdBlockResolver(BaseResolver):
    """Resolver DNS, który blokuje domeny reklamowe"""
    
    def __init__(self, upstream_dns='8.8.8.8'):
        """
        Inicjalizacja resolvera
        
        Args:
            upstream_dns: Serwer DNS do przekazywania zapytań niezablokowanych
        """
        self.upstream_dns = upstream_dns
        self.blocked_count = 0
        self.total_count = 0
        self.domain_stats = {}  # Statystyki zapytań wg domeny
    
    def is_ad_domain(self, domain):
        """Sprawdza, czy domena jest związana z reklamami"""
        for pattern in AD_PATTERNS:
            if pattern.match(domain):
                return True
        return False
    
    def resolve(self, request, handler):
        """
        Rozwiązuje zapytanie DNS. Jeśli domena jest na liście blokowanych,
        zwraca lokalny adres IP (0.0.0.0), w przeciwnym razie przekazuje zapytanie
        do prawdziwego serwera DNS.
        """
        reply = request.reply()
        qname = str(request.q.qname)
        client_ip = handler.client_address[0]
        
        self.total_count += 1
        
        # Aktualizuj statystyki domen
        domain_root = qname.split('.')[-2] if len(qname.split('.')) > 1 else qname
        self.domain_stats[domain_root] = self.domain_stats.get(domain_root, 0) + 1
        
        # Bardziej szczegółowe logowanie dla każdego zapytania
        question_type = QTYPE[request.q.qtype]
        logger.info(f"Zapytanie DNS od {client_ip}: {qname} (typ: {question_type})")
        
        if self.is_ad_domain(qname):
            # Blokuj domenę, zwracając 0.0.0.0
            self.blocked_count += 1
            logger.info(f"🚫 ZABLOKOWANO: {qname} od klienta {client_ip}")
            
            # Dla każdego pytania w zapytaniu, dodaj odpowiedź 0.0.0.0
            for question in request.questions:
                if question.qtype == QTYPE.A:
                    reply.add_answer(RR(
                        rname=question.qname,
                        rtype=QTYPE.A,
                        rclass=question.qclass,
                        ttl=300,
                        rdata=A("0.0.0.0")
                    ))
            
            # Wyświetl statystyki co 10 zablokowanych zapytań
            if self.blocked_count % 10 == 0:
                percentage = (self.blocked_count / self.total_count) * 100
                logger.info(f"Statystyki: zablokowano {self.blocked_count} z {self.total_count} zapytań ({percentage:.2f}%)")
                
        else:
            # Przekazuj inne zapytania do zewnętrznego serwera DNS
            try:
                logger.debug(f"Przekazuję zapytanie dla {qname} do {self.upstream_dns}")
                upstream_response = DNSRecord.parse(self._dns_lookup(request.pack(), self.upstream_dns))
                reply = upstream_response
                logger.debug(f"Otrzymano odpowiedź od {self.upstream_dns} dla {qname}")
            except Exception as e:
                logger.error(f"Błąd przy przekazywaniu zapytania {qname}: {e}")
                logger.error(traceback.format_exc())
        
        return reply
    
    def _dns_lookup(self, request, server):
        """Wykonuje zapytanie DNS do podanego serwera"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(request, (server, 53))
        data, _ = sock.recvfrom(8192)
        sock.close()
        return data
    
    def print_stats(self):
        """Wyświetla szczegółowe statystyki dotyczące zapytań DNS"""
        logger.info("-" * 50)
        logger.info("Statystyki zapytań DNS:")
        logger.info(f"Całkowita liczba zapytań: {self.total_count}")
        logger.info(f"Zablokowane zapytania: {self.blocked_count} ({(self.blocked_count/self.total_count*100) if self.total_count > 0 else 0:.2f}%)")
        
        if self.domain_stats:
            logger.info("Top 10 domen:")
            sorted_domains = sorted(self.domain_stats.items(), key=lambda x: x[1], reverse=True)
            for domain, count in sorted_domains[:10]:
                logger.info(f" - {domain}: {count} zapytań")
        logger.info("-" * 50)

def run_server(host='0.0.0.0', port=53, upstream_dns='8.8.8.8', interface=None):
    """Uruchamia serwer DNS"""
    
    # Sprawdź łączność z zewnętrznym serwerem DNS
    if not test_dns_connectivity():
        logger.warning("Test łączności DNS nieudany. Mogą wystąpić problemy z działaniem serwera.")
    
    # Ustawienie adresu IP na podstawie interfejsu OpenVPN, jeśli podany
    if interface:
        interfaces = get_openvpn_interfaces()
        for name, ip in interfaces:
            if name == interface:
                host = ip
                logger.info(f"Używam adresu IP {ip} na interfejsie {name}")
                break
        else:
            logger.warning(f"Nie znaleziono interfejsu OpenVPN o nazwie '{interface}'. Używam {host}.")
    
    resolver = AdBlockResolver(upstream_dns)
    # Użyj własnego handlera zamiast domyślnego
    handler = lambda *args, **kwargs: PacketCapturingDNSHandler(*args, resolver=resolver, **kwargs)
    server = DNSServer(resolver, port=port, address=host, handler=handler)
    
    logger.info(f"Uruchamianie serwera DNS na {host}:{port}")
    logger.info(f"Upstream DNS: {upstream_dns}")
    
    # Informacje o wszystkich interfejsach OpenVPN
    openvpn_interfaces = get_openvpn_interfaces()
    if openvpn_interfaces:
        logger.info("Wykryte interfejsy OpenVPN:")
        for name, ip in openvpn_interfaces:
            logger.info(f" - {name}: {ip}")
    else:
        logger.warning("Nie wykryto żadnych interfejsów OpenVPN!")
    
    # Sprawdź konfigurację OpenVPN
    check_dns_settings_in_openvpn()
    
    logger.info("=" * 60)
    logger.info("Instrukcje dla klientów OpenVPN:")
    logger.info("1. Upewnij się, że konfiguracja serwera OpenVPN zawiera linię:")
    logger.info(f"   push \"dhcp-option DNS {host}\"")
    logger.info("2. Zrestartuj serwer OpenVPN po zmianie konfiguracji:")
    logger.info("   sudo systemctl restart openvpn-server@server")
    logger.info("3. Klienci muszą ponownie połączyć się z VPN, aby zastosować nowe ustawienia DNS")
    logger.info("=" * 60)
    
    logger.info("Naciśnij Ctrl+C, aby zakończyć")
    
    # Obsługa sygnału SIGUSR1 do wyświetlania statystyk
    def print_stats_handler(signum, frame):
        resolver.print_stats()
    
    signal.signal(signal.SIGUSR1, print_stats_handler)
    logger.info("Możesz wysłać sygnał SIGUSR1, aby wyświetlić statystyki: kill -SIGUSR1 <PID>")
    
    try:
        server.start_thread()
        
        # Pętla główna z okresowym wyświetlaniem statystyk
        stats_interval = 60  # sekundy
        next_stats_time = time.time() + stats_interval
        
        while True:
            time.sleep(1)
            
            # Okresowo wyświetl statystyki
            current_time = time.time()
            if current_time >= next_stats_time:
                resolver.print_stats()
                next_stats_time = current_time + stats_interval
                
    except KeyboardInterrupt:
        logger.info("Zatrzymywanie serwera...")
    finally:
        server.stop()
        resolver.print_stats()
        logger.info(f"Serwer zatrzymany.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Blokowanie reklam YouTube poprzez filtrowanie DNS')
    parser.add_argument('--host', default='0.0.0.0', help='Adres IP serwera (domyślnie: 0.0.0.0 - wszystkie interfejsy)')
    parser.add_argument('--port', default=53, type=int, help='Port serwera DNS (domyślnie: 53)')
    parser.add_argument('--upstream', default='8.8.8.8', help='Zewnętrzny serwer DNS (domyślnie: 8.8.8.8)')
    parser.add_argument('--interface', help='Nazwa interfejsu OpenVPN (np. tun0)')
    parser.add_argument('--log', default='info', choices=['debug', 'info', 'warning', 'error'], 
                        help='Poziom logowania (domyślnie: info)')
    parser.add_argument('--test', action='store_true', help='Wykonaj tylko test łączności DNS i zakończ')
    
    args = parser.parse_args()
    
    # Ustawienie poziomu logowania
    log_level = getattr(logging, args.log.upper())
    logger.setLevel(log_level)
    
    # Tryb testu
    if args.test:
        test_dns_connectivity()
        sys.exit(0)
    
    # Sprawdź, czy skrypt jest uruchamiany z uprawnieniami roota (wymagane dla portu 53)
    if args.port < 1024 and os.geteuid() != 0:
        logger.error("Nasłuchiwanie na porcie 53 wymaga uprawnień roota. Uruchom skrypt z sudo.")
        sys.exit(1)
    
    run_server(args.host, args.port, args.upstream, args.interface) 
