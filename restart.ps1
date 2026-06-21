# Restart dashboard and run audit
$port = 8099
$py = "C:\Python312\python.exe"
$dir = "C:\Users\techai\system-dashboard"

Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

Start-Process -FilePath $py -ArgumentList "dashboard.py" -WorkingDirectory $dir `
    -WindowStyle Hidden `
    -RedirectStandardOutput "$dir\logs\dash-out.txt" `
    -RedirectStandardError "$dir\logs\dash-err.txt"

Start-Sleep -Seconds 10

$up = (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) -ne $null
Write-Host "Dashboard UP: $up"
if ($up) {
    & $py -c @"
import urllib.request, json
snap = json.loads(urllib.request.urlopen('http://127.0.0.1:8099/api/status', timeout=12).read())
s = snap['system']
print('CPU:', s['cpu_pct'], '  cores:', s['cpu_count'])
print('DRIVES:')
for lt, d in s['drives'].items():
    print(' ', lt + ': free=' + str(d['free_gb']) + 'GB  pct=' + str(d['pct']) + '%  failing=' + str(d['failing']) + '  reason=' + str(d['failing_reason']))
sh = snap.get('smart_health', {})
print('SMART drives:', list(sh.keys()) if sh else 'EMPTY')
for drv, info in sh.items():
    print(' ', drv + ':', info.get('health'), info.get('model','?'), 'temp=' + str(info.get('temp_c')), 'wear=' + str(info.get('wear_pct')))
nics = snap.get('net_health', {}).get('interfaces', {})
real_drops = [(n, v['dropped_ps']) for n, v in nics.items() if v.get('dropped_ps',0)>0 and not v.get('is_virtual')]
print('Real NIC drops:', real_drops if real_drops else 'none')
errs = []
try:
    import pathlib
    log = pathlib.Path(r'C:\Users\techai\system-dashboard\logs\dash-err.txt').read_text(errors='replace')
    errs = [l for l in log.splitlines() if 'Traceback' in l or 'TypeError' in l or 'SyntaxError' in l]
except: pass
print('Startup errors:', errs if errs else 'none')
"@
}
