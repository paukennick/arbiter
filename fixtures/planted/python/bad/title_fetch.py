import ipaddress
import socket
import urllib.request
from urllib.parse import urlparse


def _is_public_host(host):
    infos = socket.getaddrinfo(host, None)
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


def fetch_title(url):
    host = urlparse(url).hostname
    if not host or not _is_public_host(host):
        return None
    with urllib.request.urlopen(url, timeout=5) as resp:  # expect: arbiter/python.ssrf-check-then-connect
        return resp.read(65536)
