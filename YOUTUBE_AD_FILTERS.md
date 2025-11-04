# YouTube Ad Filters - Rozszerzone Funkcjonalności

## Przegląd

System blokowania reklam YouTube został rozszerzony o zaawansowaną klasyfikację reklam z rozróżnieniem na:
- **Typy reklam**: pre-roll, mid-roll, post-roll, overlay, companion
- **Właściwości**: skippable (pomijalne) vs non-skippable (niepomijalne)
- **Szczegółowe statystyki** dla każdego typu reklamy

## Nowe Komponenty

### 1. Plik Sygnatur (`ad_signatures.json`)

Centralna baza danych wzorców reklamowych zawierająca:

```json
{
  "ad_patterns": [
    {
      "name": "pre_roll_skippable",
      "type": "pre-roll",
      "skippable": true,
      "patterns": ["adpodposition=0", "preroll"],
      "heuristics": {}
    }
  ],
  "url_parameters": {
    "ad_indicators": ["oad", "ad_type", "adformat", ...]
  },
  "domains": {
    "ad_servers": ["doubleclick.net", ...],
    "googlevideo_ad_patterns": [...]
  },
  "path_patterns": {
    "ad_paths": ["/pagead/", "/ptracking", ...],
    "videoplayback_ad_indicators": [...]
  }
}
```

### 2. Klasa `AdClassifier`

Nowa klasa w `vpn_adbocker.py` odpowiedzialna za:

**Normalizację URL:**
- Dekodowanie zakodowanych parametrów
- Parsowanie parametrów zapytania
- Sortowanie i standaryzacja

**Klasyfikację reklam:**
```python
classifier = AdClassifier('ad_signatures.json')
result = classifier.classify_ad(url)
# Zwraca: (ad_type, ad_name, is_skippable) lub None
```

**Wyciąganie heurystyk:**
- `has_oad_flag` - obecność parametru `oad`
- `has_adgoogleid` - obecność identyfikatora reklamy Google
- `has_ctier_l` - poziom warstwy zawartości
- `adpodposition` - pozycja w sekwencji reklam
- `duration` - długość segmentu

### 3. Rozszerzone Statystyki

Klasa `Stats` teraz śledzi:

```python
# Statystyki według typu
stats.blocked_preroll      # Liczba zablokowanych pre-roll
stats.blocked_midroll      # Liczba zablokowanych mid-roll
stats.blocked_postroll     # Liczba zablokowanych post-roll
stats.blocked_overlay      # Liczba zablokowanych overlay
stats.blocked_companion    # Liczba zablokowanych companion

# Statystyki według właściwości
stats.blocked_skippable      # Liczba zablokowanych pomijanych
stats.blocked_nonskippable   # Liczba zablokowanych niepomijanych

# Szczegółowe statystyki
stats.blocked_by_pattern     # Słownik z liczbą dla każdego wzorca
```

**Przykładowy output:**
```
======================================================================
Statystyki blokowania reklam YouTube:
Czas działania: 3600.00 sekund
Łączna liczba pakietów: 15420
Zablokowane pakiety: 234

Zablokowane reklamy według typu:
 - Pre-roll:      98 ( 41.9%)
 - Mid-roll:      87 ( 37.2%)
 - Post-roll:     23 (  9.8%)
 - Overlay:       18 (  7.7%)
 - Companion:      5 (  2.1%)
 - Unknown:        3 (  1.3%)

Zablokowane reklamy według właściwości:
 - Skippable:        176 ( 75.2%)
 - Non-skippable:     58 ( 24.8%)
======================================================================
```

## Parametry URL Wykrywane jako Reklamy

### Główne Wskaźniki
- `oad` - "Online Ad" marker
- `ad_type` - typ reklamy
- `adformat` / `ad_format` - format reklamy
- `ctier=L` - niski poziom warstwy (często reklamy)
- `ad_break_type` - typ przerwy reklamowej (1=skippable, 2=non-skippable, 3=post, 4=post-non-skippable)
- `adpodposition` - pozycja w sekwencji reklam (0=pre-roll, 1+=mid/post-roll)
- `adtagurl` - URL tagu reklamowego
- `adgoogleid` - identyfikator reklamy Google
- `ads_tag` - tag reklamy

### Typy Reklam

#### Pre-roll (przed wideo)
- **Skippable**: `adpodposition=0` + `oad=1` + brak `ad_break_type=2`
- **Non-skippable**: `adpodposition=0` + `ad_break_type=2` lub `nonskip`

#### Mid-roll (w trakcie wideo)
- **Skippable**: `adpodposition=[1-9]` + `oad=1` + brak `nonskip`
- **Non-skippable**: `adpodposition=[1-9]` + (`nonskip` lub `bumper`)

#### Post-roll (po wideo)
- **Skippable**: `postroll` + brak `nonskip`
- **Non-skippable**: `postroll` + `nonskip` lub `ad_break_type=4`

#### Overlay/Banner
- `ad_format=overlay` lub `ad_format=banner`
- `/pagead/interaction`

#### Companion Ads
- `ad_format=companion`
- `/pagead/adunit/companion`

## Domeny Reklamowe

### Główne Domeny
- `doubleclick.net` - główna sieć reklamowa Google
- `googlesyndication.com` - syndykacja reklam
- `googleadservices.com` - usługi reklamowe
- `google-analytics.com` - analityka
- `innovid.com` - platforma wideo reklamowego
- `2mdn.net` - CDN reklam

### Wzorce Google Video (2024/2025)
```regex
r[0-9]+\.sn-[a-z0-9-]+\.googlevideo\.com
r[0-9]+---sn-[a-z0-9]{8}\.googlevideo\.com
r[0-9]+\.sn-[a-z0-9]+-[a-z0-9]{4}\.googlevideo\.com
redirector\.googlevideo\.com
```

## Ścieżki Reklamowe

### YouTube API
- `/pagead/` - reklamy stronicowe
- `/ptracking` - śledzenie odtwarzania reklam
- `/_get_ads` - pobieranie reklam
- `/api/stats/ads` - statystyki reklam
- `/api/stats/ads_break` - statystyki przerw reklamowych
- `/get_midroll_info` - informacje o mid-roll
- `/youtubei/v1/player/ad` - API odtwarzacza reklam

### Video Playback
- `/videoplayback.*oad` - odtwarzanie reklam
- `/videoplayback.*ctier=L` - niska warstwa (reklamy)
- `/videoplayback.*ad_break` - przerwy reklamowe
- `/videoplayback.*adpodposition` - pozycja w sekwencji

## Użycie

### Podstawowe Użycie

```bash
# Uruchom z domyślnymi ustawieniami
sudo python3 vpn_adbocker.py

# Określ interfejs VPN
sudo python3 vpn_adbocker.py --interface tun0

# Określ podsieć VPN
sudo python3 vpn_adbocker.py --subnet 10.8.0.0/24

# Tryb debug
sudo python3 vpn_adbocker.py --log debug
```

### Wyświetlanie Statystyk

Wyślij sygnał SIGUSR1 do procesu:
```bash
kill -SIGUSR1 $(pgrep -f vpn_adbocker)
```

## Testy

### Testy Jednostkowe

```bash
# Uruchom wszystkie testy jednostkowe
python3 test_ad_classifier.py

# Testy obejmują:
# - Klasyfikację pre/mid/post-roll
# - Rozróżnienie skippable/non-skippable
# - Overlay i companion ads
# - Brak fałszywych trafień dla zwykłego wideo
# - Normalizację URL i heurystyki
```

### Testy Integracyjne

```bash
# Uruchom testy integracyjne
python3 test_integration.py

# Testy obejmują:
# - Przetwarzanie rzeczywistych payloadów HTTP
# - Weryfikację statystyk
# - Normalizację URL
```

### Przykładowe Payloady

```bash
# Wyświetl dostępne payloady testowe
python3 test_payloads.py
```

## Przykłady Rozpoznawanych Reklam

### Pre-roll Skippable
```
https://r5---sn-aigl6nls.googlevideo.com/videoplayback?id=abc123&oad=1&adpodposition=0&ctier=L
🚫 Blokowanie reklamy [pre-roll, skippable]
```

### Mid-roll Non-skippable
```
https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=2&nonskip=1
🚫 Blokowanie reklamy [mid-roll, non-skippable]
```

### Overlay Banner
```
https://www.youtube.com/pagead/interaction/?ad_format=overlay
🚫 Blokowanie reklamy [overlay, skippable]
```

## Konfiguracja Zaawansowana

### Modyfikacja Sygnatur

Edytuj `ad_signatures.json` aby dodać nowe wzorce:

```json
{
  "name": "custom_ad_pattern",
  "type": "mid-roll",
  "skippable": false,
  "patterns": [
    "your_custom_pattern",
    "another_pattern"
  ],
  "heuristics": {}
}
```

### Kolejność Wzorców

Wzorce są sprawdzane w kolejności z pliku JSON. Umieść bardziej szczegółowe wzorce (np. non-skippable) przed ogólnymi (skippable).

## Walidacja

### Brak Fałszywych Trafień

System został przetestowany aby zapewnić brak blokowania:
- Zwykłych strumieni wideo
- Miniatur
- Plików JavaScript odtwarzacza
- API stats (bez parametrów reklamowych)
- Plików obrazów

### Pokrycie

Testy weryfikują:
- ✅ 12 typów payloadów reklamowych (100% zablokowanych)
- ✅ 7 typów payloadów zwykłego wideo (0% fałszywych trafień)
- ✅ Wszystkie typy reklam (pre/mid/post, skippable/non-skippable)
- ✅ Najnowsze wzorce z 2024/2025

## Kompatybilność

### Windows (PyDivert)
- Przechwytywanie pakietów przez WinDivert
- Filtrowanie na poziomie kernela
- Wspiera interfejsy TAP-Windows

### Linux (NetfilterQueue + Scapy)
- Automatyczna konfiguracja iptables
- NFQUEUE dla efektywnego przetwarzania
- Wspiera interfejsy tun/tap

## Wydajność

- Skompilowane wyrażenia regularne dla szybkiego dopasowania
- Normalizacja URL z cache'owaniem
- Sprawdzanie heurystyk tylko gdy wymagane
- Minimalne opóźnienie pakietów (<1ms)

## Troubleshooting

### Reklamy Nie Są Blokowane

1. Sprawdź czy klasyfikator się załadował:
   ```
   Załadowano klasyfikator reklam z X wzorcami
   ```

2. Włącz tryb debug:
   ```bash
   sudo python3 vpn_adbocker.py --log debug
   ```

3. Sprawdź czy plik `ad_signatures.json` istnieje

### Fałszywe Trafienia

1. Sprawdź logi dla zablokowanych URL
2. Dodaj wyjątek w `ad_signatures.json`
3. Zgłoś problem z przykładowym URL

## Rozwój

### Dodawanie Nowych Wzorców

1. Zbierz przykładowe URL-e reklam
2. Zidentyfikuj wspólne parametry/wzorce
3. Dodaj do `ad_signatures.json`
4. Dodaj testy w `test_ad_classifier.py`
5. Uruchom testy: `python3 test_ad_classifier.py`

### Zgłaszanie Problemów

Przy zgłaszaniu problemów dołącz:
- Przykładowy URL (bez danych osobowych)
- Typ reklamy (pre/mid/post-roll)
- Czy została zablokowana
- Logi z trybu debug

## Licencja

Ten projekt jest częścią systemu blokowania reklam YouTube w VPN.
