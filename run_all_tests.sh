#!/bin/bash
# Skrypt uruchamiający wszystkie testy dla rozszerzonych filtrów YouTube

echo "========================================================================"
echo "ROZSZERZONE FILTRY YOUTUBE - PAKIET TESTOWY"
echo "========================================================================"
echo ""

# Kolory
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test 1: Sprawdź czy pliki istnieją
echo "📁 Test 1: Sprawdzanie plików..."
FILES=(
    "ad_signatures.json"
    "vpn_adbocker.py"
    "adblocker.py"
    "test_ad_classifier.py"
    "test_integration.py"
    "test_payloads.py"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   ✅ $file"
    else
        echo "   ❌ $file - BRAK!"
        ((FAILED_TESTS++))
    fi
    ((TOTAL_TESTS++))
done

echo ""

# Test 2: Sprawdź czy ad_signatures.json jest prawidłowym JSON
echo "🔍 Test 2: Walidacja ad_signatures.json..."
((TOTAL_TESTS++))
if python3 -c "import json; json.load(open('ad_signatures.json'))" 2>/dev/null; then
    echo "   ✅ Plik JSON jest prawidłowy"
    ((PASSED_TESTS++))
else
    echo "   ❌ Plik JSON jest nieprawidłowy"
    ((FAILED_TESTS++))
fi

echo ""

# Test 3: Sprawdź import modułów
echo "📦 Test 3: Import modułów Python..."
((TOTAL_TESTS++))
if python3 -c "from vpn_adbocker import AdClassifier, Stats, YouTubeAdBlocker" 2>/dev/null; then
    echo "   ✅ Moduły importują się poprawnie"
    ((PASSED_TESTS++))
else
    echo "   ❌ Błąd importu modułów"
    ((FAILED_TESTS++))
fi

echo ""

# Test 4: Uruchom testy jednostkowe
echo "🧪 Test 4: Testy jednostkowe (test_ad_classifier.py)..."
((TOTAL_TESTS++))
if python3 test_ad_classifier.py > /tmp/test_unit.log 2>&1; then
    UNIT_TESTS=$(grep "Uruchomiono testów:" /tmp/test_unit.log | awk '{print $3}')
    UNIT_SUCCESS=$(grep "Sukces:" /tmp/test_unit.log | awk '{print $2}')
    echo "   ✅ Testy jednostkowe: $UNIT_SUCCESS/$UNIT_TESTS zaliczonych"
    ((PASSED_TESTS++))
else
    echo "   ❌ Testy jednostkowe nie powiodły się"
    ((FAILED_TESTS++))
    tail -20 /tmp/test_unit.log
fi

echo ""

# Test 5: Uruchom testy integracyjne
echo "🔧 Test 5: Testy integracyjne (test_integration.py)..."
((TOTAL_TESTS++))
if python3 test_integration.py > /tmp/test_integration.log 2>&1; then
    INT_TESTS=$(grep "Uruchomiono testów:" /tmp/test_integration.log | awk '{print $3}')
    INT_SUCCESS=$(grep "Sukces:" /tmp/test_integration.log | awk '{print $2}')
    echo "   ✅ Testy integracyjne: $INT_SUCCESS/$INT_TESTS zaliczonych"
    ((PASSED_TESTS++))
else
    echo "   ❌ Testy integracyjne nie powiodły się"
    ((FAILED_TESTS++))
    tail -20 /tmp/test_integration.log
fi

echo ""

# Test 6: Sprawdź payloady testowe
echo "📊 Test 6: Payloady testowe..."
((TOTAL_TESTS++))
if python3 test_payloads.py > /tmp/test_payloads.log 2>&1; then
    PAYLOAD_COUNT=$(grep "Łącznie payloadów:" /tmp/test_payloads.log | awk '{print $3}')
    echo "   ✅ Payloady testowe: $PAYLOAD_COUNT dostępnych"
    ((PASSED_TESTS++))
else
    echo "   ❌ Błąd w payloadach testowych"
    ((FAILED_TESTS++))
fi

echo ""

# Test 7: Test klasyfikatora na przykładowych URL-ach
echo "🎯 Test 7: Klasyfikacja przykładowych URL-i..."
((TOTAL_TESTS++))
python3 << 'PYTHON_SCRIPT' > /tmp/test_classifier.log 2>&1
from vpn_adbocker import AdClassifier

classifier = AdClassifier('ad_signatures.json')

test_cases = [
    ("https://r5---sn-aigl6nls.googlevideo.com/videoplayback?oad=1&adpodposition=0", True, "pre-roll"),
    ("https://r5---sn-aigl6nls.googlevideo.com/videoplayback?id=abc&itag=22", False, None),
    ("https://www.youtube.com/pagead/interaction/?ad_format=overlay", True, "overlay"),
]

success = 0
total = len(test_cases)

for url, should_block, expected_type in test_cases:
    result = classifier.classify_ad(url)
    if should_block:
        if result and result[0] == expected_type:
            success += 1
        else:
            print(f"FAIL: {url[:60]}... - Expected {expected_type}, got {result}")
    else:
        if result is None:
            success += 1
        else:
            print(f"FAIL: {url[:60]}... - Expected None, got {result}")

print(f"Klasyfikacja: {success}/{total} poprawnych")
exit(0 if success == total else 1)
PYTHON_SCRIPT

if [ $? -eq 0 ]; then
    CLASSIFIER_RESULT=$(grep "Klasyfikacja:" /tmp/test_classifier.log)
    echo "   ✅ $CLASSIFIER_RESULT"
    ((PASSED_TESTS++))
else
    echo "   ❌ Błąd klasyfikacji"
    ((FAILED_TESTS++))
    cat /tmp/test_classifier.log
fi

echo ""

# Podsumowanie
echo "========================================================================"
echo "PODSUMOWANIE"
echo "========================================================================"
echo ""
echo "Wykonanych testów: $TOTAL_TESTS"
echo -e "Zaliczonych:       ${GREEN}$PASSED_TESTS${NC}"
echo -e "Niezaliczonych:    ${RED}$FAILED_TESTS${NC}"
echo ""

SUCCESS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo "Współczynnik sukcesu: $SUCCESS_RATE%"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✅ WSZYSTKIE TESTY ZALICZONE!${NC}"
    echo ""
    echo "System rozszerzonych filtrów YouTube jest gotowy do użycia."
    exit 0
else
    echo -e "${RED}❌ NIEKTÓRE TESTY NIE POWIODŁY SIĘ${NC}"
    echo ""
    echo "Sprawdź logi w /tmp/test_*.log"
    exit 1
fi
