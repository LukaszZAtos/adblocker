#!/usr/bin/env python3
import socket
import time
import threading
from dnslib import DNSRecord, RR, QTYPE, A, DNSHeader
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import argparse
import re
import logging
import sys
import os
import subprocess
import ipaddress

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
    r'r[0-9]+-+sn-.*.googlevideo.com'
]

# Kompilacja wyrażeń regularnych dla szybszego dopasowania
AD_PATTERNS = [re.compile(pattern) for pattern in AD_DOMAINS]

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
        logger.debug(f"Zapytanie od {client_ip} dla {qname}")
        
        if self.is_ad_domain(qname):
            # Blokuj domenę, zwracając 0.0.0.0
            self.blocked_count += 1
            logger.info(f"Zablokowano: {qname} od klienta {client_ip}")
            
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
            
            # Wyświetl statystyki
            if self.blocked_count % 10 == 0:
                percentage = (self.blocked_count / self.total_count) * 100
                logger.info(f"Statystyki: zablokowano {self.blocked_count} z {self.total_count} zapytań ({percentage:.2f}%)")
                
        else:
            # Przekazuj inne zapytania do zewnętrznego serwera DNS
            try:
                upstream_response = DNSRecord.parse(self._dns_lookup(request.pack(), self.upstream_dns))
                reply = upstream_response
            except Exception as e:
                logger.error(f"Błąd przy przekazywaniu zapytania: {e}")
        
        return reply
    
    def _dns_lookup(self, request, server):
        """Wykonuje zapytanie DNS do podanego serwera"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(request, (server, 53))
        data, _ = sock.recvfrom(8192)
        sock.close()
        return data

def run_server(host='0.0.0.0', port=53, upstream_dns='8.8.8.8', interface=None):
    """Uruchamia serwer DNS"""
    
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
    server = DNSServer(resolver, port=port, address=host)
    
    logger.info(f"Uruchamianie serwera DNS na {host}:{port}")
    logger.info(f"Upstream DNS: {upstream_dns}")
    
    # Informacje o wszystkich interfejsach OpenVPN
    openvpn_interfaces = get_openvpn_interfaces()
    if openvpn_interfaces:
        logger.info("Wykryte interfejsy OpenVPN:")
        for name, ip in openvpn_interfaces:
            logger.info(f" - {name}: {ip}")
    
    logger.info("Naciśnij Ctrl+C, aby zakończyć")
    
    try:
        server.start_thread()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Zatrzymywanie serwera...")
    finally:
        server.stop()
        logger.info(f"Serwer zatrzymany. Zablokowano łącznie {resolver.blocked_count} z {resolver.total_count} zapytań.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Blokowanie reklam YouTube poprzez filtrowanie DNS')
    parser.add_argument('--host', default='0.0.0.0', help='Adres IP serwera (domyślnie: 0.0.0.0 - wszystkie interfejsy)')
    parser.add_argument('--port', default=53, type=int, help='Port serwera DNS (domyślnie: 53)')
    parser.add_argument('--upstream', default='8.8.8.8', help='Zewnętrzny serwer DNS (domyślnie: 8.8.8.8)')
    parser.add_argument('--interface', help='Nazwa interfejsu OpenVPN (np. tun0)')
    parser.add_argument('--log', default='info', choices=['debug', 'info', 'warning', 'error'], 
                        help='Poziom logowania (domyślnie: info)')
    
    args = parser.parse_args()
    
    # Ustawienie poziomu logowania
    log_level = getattr(logging, args.log.upper())
    logger.setLevel(log_level)
    
    # Sprawdź, czy skrypt jest uruchamiany z uprawnieniami roota (wymagane dla portu 53)
    if args.port < 1024 and os.geteuid() != 0:
        logger.error("Nasłuchiwanie na porcie 53 wymaga uprawnień roota. Uruchom skrypt z sudo.")
        sys.exit(1)
    
    run_server(args.host, args.port, args.upstream, args.interface) 
