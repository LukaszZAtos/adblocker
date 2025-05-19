# YouTube VPN AdBlocker

Program do blokowania reklam YouTube w ruchu sieciowym poprzez monitorowanie i filtrowanie pakietów w środowisku VPN.

## Opis

YouTube VPN AdBlocker to narzędzie służące do blokowania reklam YouTube poprzez analizę ruchu sieciowego na interfejsach VPN. Program wykrywa i blokuje pakiety zawierające wzorce URL charakterystyczne dla reklam, co pozwala na efektywne blokowanie reklam bez konieczności instalowania dodatków w przeglądarce.

## Jak to działa

Skrypt `vpn_adblocker.py` działa na poziomie sieci, a nie jako rozszerzenie przeglądarki. Oto szczegółowe wyjaśnienie jego działania:

1. **Przechwytywanie pakietów sieciowych**:
   - Na Windows używa biblioteki `PyDivert` do przechwytywania pakietów
   - Na Linuxie wykorzystuje `NetfilterQueue` i `iptables` do przekierowania ruchu HTTP/HTTPS

2. **Detekcja reklam**:
   - Skrypt przeszukuje przechodzące pakiety HTTP/HTTPS
   - Wyodrębnia adresy URL z ruchu sieciowego
   - Porównuje je z rozbudowaną bazą wzorców reklamowych (regex) dla YouTube

3. **Mechanizm blokowania**:
   - Jeśli adres URL pasuje do wzorca reklamy, pakiet jest odrzucany
   - Na Linuxie używa `iptables` do odrzucania pakietów
   - Na Windows blokuje pakiety poprzez `PyDivert`

4. **Automatyczna konfiguracja**:
   - Wykrywa interfejsy VPN i odpowiednie podsieci
   - Konfiguruje reguły `iptables` (Linux) automatycznie
   - Czyszczenie reguł po zakończeniu pracy skryptu

5. **Analiza w czasie rzeczywistym**:
   - Analizuje nagłówki HTTP i dane TLS
   - Rozpoznaje wzorce charakterystyczne dla reklam YouTube
   - Blokuje zarówno reklamy w formie pre-roll, mid-roll jak i bannery

6. **Zbieranie statystyk**:
   - Zlicza liczbę przeanalizowanych pakietów
   - Liczy zablokowane pakiety reklamowe
   - Pokazuje listę najczęściej blokowanych domen reklamowych
   - Prezentuje raporty dotyczące efektywności blokowania

Kluczową zaletą tego rozwiązania jest to, że działa na poziomie sieci, więc blokuje reklamy dla wszystkich urządzeń korzystających z VPN, bez potrzeby instalacji dodatkowych wtyczek w przeglądarkach. Jest to szczególnie przydatne w środowiskach domowych, gdzie wiele urządzeń (włącznie z telefonami, smart TV) korzysta z jednego łącza VPN.

### Główne funkcje

- Automatyczne wykrywanie interfejsów i podsieci VPN
- Blokowanie reklam YouTube w czasie rzeczywistym
- Wyświetlanie statystyk blokowania
- Kompatybilność z systemami Windows, Debian i CentOS

## Wymagania

### Windows
- Python 3.6 lub nowszy
- Biblioteka PyDivert

### Linux (Debian/Ubuntu)
- Python 3.6 lub nowszy
- Biblioteka NetfilterQueue
- Scapy
- Uprawnienia administratora (root)

### Linux (CentOS/RHEL/Oracle Linux)
- Python 3.6 lub nowszy
- Biblioteka NetfilterQueue
- Scapy
- Uprawnienia administratora (root)

## Instalacja

### Debian/Ubuntu

```bash
# Aktualizacja repozytoriów
sudo apt-get update

# Instalacja Pythona i wymaganych narzędzi systemowych
sudo apt-get install -y python3 python3-pip python3-dev

# Instalacja zależności do kompilacji NetfilterQueue
sudo apt-get install -y libnfnetlink-dev libnetfilter-queue-dev

# Instalacja wymaganych bibliotek Pythona
sudo pip3 install NetfilterQueue scapy
```

### Windows

```bash
# Instalacja wymaganych bibliotek Pythona
pip install pydivert

# Instalacja dodatkowych zależności (opcjonalnie)
pip install psutil
```

### CentOS/RHEL/Oracle Linux

```bash
# Aktualizacja repozytoriów
sudo yum update

# Instalacja grupy narzędzi deweloperskich
sudo yum groupinstall -y "Development Tools"

# Instalacja Pythona i wymaganych narzędzi systemowych
sudo yum install -y python3 python3-pip python3-devel

# Instalacja zależności do kompilacji NetfilterQueue
sudo yum install -y libnfnetlink-devel libnetfilter_queue-devel

# Instalacja wymaganych bibliotek Pythona
sudo pip3 install NetfilterQueue scapy
```

## Użycie

### Podstawowe uruchomienie

```bash
# Linux (jako root)
sudo python3 vpn_adblocker.py

# Windows (jako administrator)
python vpn_adblocker.py
```

### Zaawansowane opcje

```bash
# Określenie interfejsu VPN
python3 vpn_adblocker.py --interface tun0

# Określenie podsieci VPN
python3 vpn_adblocker.py --subnet 10.8.0.0/24

# Ustawienie poziomu logowania
python3 vpn_adblocker.py --log debug
```

## Rozwiązywanie problemów

### Linux

1. **Błąd: "Brak wymaganych bibliotek!"**
   - Upewnij się, że zainstalowałeś NetfilterQueue i Scapy:
   ```bash
   sudo pip3 install NetfilterQueue scapy
   ```

2. **Błąd podczas kompilacji NetfilterQueue**
   - Upewnij się, że zainstalowałeś wymagane pakiety deweloperskie:
   ```bash
   # Debian/Ubuntu
   sudo apt-get install -y libnfnetlink-dev libnetfilter-queue-dev
   
   # CentOS/RHEL
   sudo yum install -y libnfnetlink-devel libnetfilter_queue-devel
   ```

3. **Błędy reguł iptables**
   - Upewnij się, że masz uprawnienia root (sudo)
   - Sprawdź istniejące reguły iptables: `sudo iptables -L`

### Windows

1. **Błąd: "Brak wymaganych bibliotek!"**
   - Upewnij się, że zainstalowałeś PyDivert:
   ```bash
   pip install pydivert
   ```
