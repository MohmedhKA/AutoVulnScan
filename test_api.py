import requests
import os

token = os.environ.get('VULNCHECK_TOKEN', '')
print(f'Token loaded: {token[:20]}...{token[-4:]}')

headers = {'Authorization': f'Bearer {token}'}
resp = requests.get(
    'https://api.vulncheck.com/v3/index/nist-nvd2',
    params={'keyword': 'vsftpd'},
    headers=headers,
    timeout=10
)

print(f'Status code: {resp.status_code}')

if resp.status_code == 200:
    data = resp.json()
    items = data.get('data', [])
    print(f'Results returned: {len(items)}')
    if items:
        cve = items[0].get('cve', {})
        print(f'First CVE ID: {cve.get("id", "unknown")}')
        print('API WORKING ✅')
    else:
        print('API connected but returned 0 results ⚠️')

elif resp.status_code == 401:
    print('Token rejected — wrong token or expired ❌')

elif resp.status_code == 403:
    print('Forbidden — free tier cannot access nist-nvd2 index ❌')
    print('Try this endpoint instead:')
    print('  https://api.vulncheck.com/v3/index/initial-access')

elif resp.status_code == 429:
    print('Rate limited — wait a bit and retry ⏳')

else:
    print(f'Unexpected error ({resp.status_code}):')
    print(resp.text[:300])
