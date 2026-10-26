import ipaddress
import socket
import urllib.request
from urllib.parse import urlparse


def _is_public_host(host):
    infos = socket.getaddrinfo(host, None)
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


def fetch_title(url, create_connection=socket.create_connection):
    host = urlparse(url).hostname
    if not host or not _is_public_host(host):
        return None
    sock = create_connection((host, 443), timeout=5)
    sock.close()
    return None
