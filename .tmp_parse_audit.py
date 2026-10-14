import json, io, sys
sys.stdout.reconfigure(encoding='utf-8')
rows = []
for line in io.open('.tmp_waf_audit.log', encoding='utf-8', errors='ignore'):
    line = line.strip()
    if not line.startswith('{'):
        continue
    try:
        j = json.loads(line)
    except Exception:
        continue
    t = j.get('transaction', {})
    ids = []
    for m in t.get('messages', []):
        rid = str(m.get('details', {}).get('ruleId', ''))
        if rid.startswith('300'):
            ids.append(rid)
    if ids:
        rq = t.get('request', {})
        rows.append((t.get('time', '?'), rq.get('method', '?'), str(rq.get('uri', ''))[:70], sorted(set(ids))))
print('total transactions:', sum(1 for l in io.open('.tmp_waf_audit.log', encoding='utf-8', errors='ignore') if l.startswith('{')))
for r in rows:
    print(r)
