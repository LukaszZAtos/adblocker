#!/usr/bin/env python3
"""
Przykładowe payloady HTTP/HTTPS dla testowania klasyfikatora
Symulują prawdziwy ruch YouTube z reklamami i bez reklam
"""

# Próbki ruchu reklamowego (powinny być zablokowane)
AD_PAYLOADS = {
    "pre_roll_skippable": b"""GET /videoplayback?expire=1234567890&ei=abc123&ip=1.2.3.4&id=o-AB123&itag=22&source=youtube&requiressl=yes&oad=1&adpodposition=0&ctier=L&ad_type=video_click_to_play HTTP/1.1\r
Host: r5---sn-aigl6nls.googlevideo.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "pre_roll_nonskippable": b"""GET /videoplayback?expire=1234567890&ei=abc123&ip=1.2.3.4&id=o-AB123&itag=22&source=youtube&requiressl=yes&oad=1&adpodposition=0&ad_break_type=2&ctier=L HTTP/1.1\r
Host: r5---sn-aigl6nls.googlevideo.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "mid_roll_skippable": b"""GET /videoplayback?expire=1234567890&ei=abc123&ip=1.2.3.4&id=o-AB123&itag=22&source=youtube&requiressl=yes&oad=1&adpodposition=1&adgoogleid=xyz789 HTTP/1.1\r
Host: r3---sn-4g5e6nzz.googlevideo.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "mid_roll_nonskippable": b"""GET /videoplayback?expire=1234567890&ei=abc123&ip=1.2.3.4&id=o-AB123&itag=22&source=youtube&requiressl=yes&oad=1&adpodposition=2&nonskip=1&ctier=L HTTP/1.1\r
Host: r5---sn-aigl6nls.googlevideo.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "post_roll": b"""GET /api/stats/ads?docid=abc123&el=detailpage&postroll=true&ad_type=video HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: application/json\r
Connection: keep-alive\r
\r
""",
    
    "overlay_banner": b"""GET /pagead/interaction/?ad_format=overlay&client=ca-pub-123456 HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "companion_ad": b"""GET /pagead/adunit/companion?type=companion_ad&video_id=abc123 HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "doubleclick_ad": b"""GET /ads/tracking?id=12345&event=impression HTTP/1.1\r
Host: doubleclick.net\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "youtube_pagead": b"""GET /pagead/adview?ai=abc123&client=ca-pub-987654 HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "youtube_ptracking": b"""GET /ptracking?event=start&ad_id=123&video_id=abc HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "get_midroll": b"""GET /get_midroll_info?ei=abc123&video_id=xyz789 HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "modern_ad_2024": b"""GET /videoplayback?expire=1234567890&ei=abc123&oad=1&adbreaktype=1&adtagurl=http://ad.example.com HTTP/1.1\r
Host: r15---sn-4g5e6nez.googlevideo.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
}

# Próbki zwykłego ruchu wideo (NIE powinny być zablokowane)
NORMAL_VIDEO_PAYLOADS = {
    "regular_video": b"""GET /videoplayback?expire=1234567890&ei=abc123&ip=1.2.3.4&id=o-AB123456789&itag=22&source=youtube&requiressl=yes&mime=video/mp4 HTTP/1.1\r
Host: r5---sn-aigl6nls.googlevideo.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Range: bytes=0-1048575\r
Connection: keep-alive\r
\r
""",
    
    "video_with_itag": b"""GET /videoplayback?expire=1234567890&ei=abc123&ip=1.2.3.4&id=xyz789&itag=18&source=youtube&requiressl=yes&mime=video%2Fmp4 HTTP/1.1\r
Host: r3---sn-4g5e6nzz.googlevideo.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "youtube_watch": b"""GET /watch?v=dQw4w9WgXcQ HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: text/html\r
Connection: keep-alive\r
\r
""",
    
    "video_info": b"""GET /get_video_info?video_id=abc123&el=detailpage HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "thumbnail": b"""GET /vi/abc123/hqdefault.jpg HTTP/1.1\r
Host: i.ytimg.com\r
User-Agent: Mozilla/5.0\r
Accept: image/webp,image/*\r
Connection: keep-alive\r
\r
""",
    
    "player_js": b"""GET /yts/jsbin/player-vflset/en_US/base.js HTTP/1.1\r
Host: s.ytimg.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
    
    "qoe_stats": b"""GET /api/stats/qoe?docid=abc123&fmt=720p&event=streamingstats HTTP/1.1\r
Host: www.youtube.com\r
User-Agent: Mozilla/5.0\r
Accept: */*\r
Connection: keep-alive\r
\r
""",
}

# Próbki HTTPS (TLS Handshake with SNI)
HTTPS_PAYLOADS = {
    "https_ad_domain": bytes([
        0x16, 0x03, 0x01,  # TLS Handshake
        0x00, 0x9a,        # Length
        0x01, 0x00, 0x00, 0x96,  # Client Hello
    ]) + b'\x00' * 80 + b'\x00\x00\x13' + b'doubleclick.net',
    
    "https_regular_video": bytes([
        0x16, 0x03, 0x01,
        0x00, 0x9a,
        0x01, 0x00, 0x00, 0x96,
    ]) + b'\x00' * 80 + b'\x00\x00\x18' + b'r5---sn-aigl6nls.googlevideo.com',
}

def get_all_payloads():
    """Zwróć wszystkie payloady z metadanymi"""
    payloads = []
    
    for name, data in AD_PAYLOADS.items():
        payloads.append({
            'name': name,
            'data': data,
            'is_ad': True,
            'type': 'http'
        })
    
    for name, data in NORMAL_VIDEO_PAYLOADS.items():
        payloads.append({
            'name': name,
            'data': data,
            'is_ad': False,
            'type': 'http'
        })
    
    for name, data in HTTPS_PAYLOADS.items():
        payloads.append({
            'name': name,
            'data': data,
            'is_ad': 'ad_domain' in name,
            'type': 'https'
        })
    
    return payloads

if __name__ == '__main__':
    """Wyświetl informacje o payloadach"""
    payloads = get_all_payloads()
    
    print("=" * 70)
    print("DOSTĘPNE PAYLOADY TESTOWE")
    print("=" * 70)
    print(f"\nŁącznie payloadów: {len(payloads)}")
    print(f"Payloadów reklamowych: {sum(1 for p in payloads if p['is_ad'])}")
    print(f"Payloadów zwykłego wideo: {sum(1 for p in payloads if not p['is_ad'])}")
    
    print("\nPayloady reklamowe:")
    for p in payloads:
        if p['is_ad']:
            print(f" - {p['name']} ({p['type']})")
    
    print("\nPayloady zwykłego wideo:")
    for p in payloads:
        if not p['is_ad']:
            print(f" - {p['name']} ({p['type']})")
    
    print("=" * 70)
