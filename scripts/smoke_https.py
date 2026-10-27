#!/usr/bin/env python3
import http.client
import ssl
import sys


def main():
    certificate = sys.argv[1] if len(sys.argv) > 1 else "nginx/certs/nginx.crt"
    context = ssl.create_default_context(cafile=certificate)
    https = http.client.HTTPSConnection("localhost", 443, context=context, timeout=5)
    https.request("GET", "/login")
    secure_response = https.getresponse()
    secure_status = secure_response.status
    secure_response.read()
    https.close()
    if secure_status != 200:
        raise RuntimeError(f"HTTPS login returned {secure_status}")

    client = http.client.HTTPConnection("localhost", 80, timeout=5)
    client.request("GET", "/login")
    response = client.getresponse()
    location = response.getheader("Location")
    client.close()
    if response.status != 301 or location != "https://localhost/login":
        raise RuntimeError(f"HTTP redirect was {response.status}, Location={location!r}")
    print("HTTPS /login: 200; HTTP /login: 301 to https://localhost/login")


if __name__ == "__main__":
    main()
