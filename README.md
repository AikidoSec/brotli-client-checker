# Brotli client test server

Online version: https://brotli.aikidosec.com/

Test clients for CVE-2026-111497. **May crash vulnerable clients.**

Requires Python 3.9+; no dependencies.

```sh
python3 checker.py
```

Examples:

```sh
node -e "fetch('http://127.0.0.1:3000/br?force_br=true')"

php -r '$ch = curl_init("http://127.0.0.1:3000/br"); curl_setopt($ch, CURLOPT_ACCEPT_ENCODING, ""); curl_exec($ch);'

python3 -c "import faulthandler; faulthandler.enable(); import requests; requests.get('http://127.0.0.1:3000/br')"

curl --compressed http://127.0.0.1:3000/br

git clone http://127.0.0.1:3000/br
```
