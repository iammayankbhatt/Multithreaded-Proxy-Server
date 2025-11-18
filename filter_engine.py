"""
Filter engine: domain blocklist, ad-domain list, simple URL path matching.
Provides helper functions to check if a request should be blocked or treated specially.
"""

import os
from urllib.parse import urlparse

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
BLOCKED_PATH = os.path.join(DATA_DIR, 'blocked_domains.txt')
AD_PATH = os.path.join(DATA_DIR, 'ad_domains.txt')

def load_list(path):
    if not os.path.exists(path):
        return set()
    with open(path, 'r', encoding='utf-8') as f:
        items = set()
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            items.add(s.lower())
        return items

def save_list(path, items_set):
    with open(path, 'w', encoding='utf-8') as f:
        for it in sorted(items_set):
            f.write(it + '\n')

blocked_domains = load_list(BLOCKED_PATH)
ad_domains = load_list(AD_PATH)

def host_from_netloc(netloc: str):
    # strip port
    if not netloc:
        return ''
    if ':' in netloc:
        return netloc.split(':', 1)[0].lower()
    return netloc.lower()

def is_blocked_host(host: str) -> bool:
    h = host.lower()
    # exact match or endswith pattern (e.g., adserver.com matches sub.adserver.com)
    if h in blocked_domains:
        return True
    for blocked in blocked_domains:
        if blocked.startswith('.'):
            # domain suffix entry .example.com matches sub.example.com
            if h.endswith(blocked):
                return True
        else:
            if h == blocked or h.endswith('.' + blocked):
                return True
    return False

def is_ad_host(host: str) -> bool:
    if not host:
        return False
    h = host.lower()
    if h in ad_domains:
        return True
    for ad in ad_domains:
        if ad.startswith('.'):
            if h.endswith(ad):
                return True
        else:
            if h == ad or h.endswith('.' + ad):
                return True
    return False

def add_blocked(domain: str):
    domain = domain.strip().lower()
    if not domain:
        return
    blocked_domains.add(domain)
    save_list(BLOCKED_PATH, blocked_domains)

def remove_blocked(domain: str):
    domain = domain.strip().lower()
    if domain in blocked_domains:
        blocked_domains.remove(domain)
        save_list(BLOCKED_PATH, blocked_domains)
