#!/usr/bin/env python3
"""Re-embeds 'CP Linux Checklist.txt' into 'CP Checklist Tracker.html'.

Run it after editing the checklist:   python3 update-tracker.py
Both files must sit next to this script. Progress saved in the browser is kept.
"""
import os, re, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
txt_path = os.path.join(here, 'CP Linux Checklist.txt')
html_path = os.path.join(here, 'CP Checklist Tracker.html')

try:
    t = open(txt_path, encoding='utf-8-sig').read()
    h = open(html_path, encoding='utf-8').read()
except OSError as e:
    sys.exit('Cannot read file: %s' % e)

t = t.replace('\r\n', '\n').replace('\r', '\n').strip('\n')
if not t.strip():
    sys.exit('The checklist is empty - not updating.')
if '\x00' in t:
    sys.exit('The checklist contains binary data - not updating.')
if re.search(r'</script|<!--', t, re.I):
    sys.exit('The checklist contains "</script" or "<!--" - remove it and run again.')

pat = re.compile(r'(<script type="text/plain" id="src">)(.*?)(</script>)', re.S)
if len(pat.findall(h)) != 1:
    sys.exit('Could not find the embedded checklist block in the HTML - not updating.')

new = pat.sub(lambda m: m.group(1) + t + m.group(3), h, count=1)
if new == h:
    print('Already up to date.')
    sys.exit(0)

fd, tmp = tempfile.mkstemp(dir=here, suffix='.tmp')
with os.fdopen(fd, 'w', encoding='utf-8') as f:
    f.write(new)
os.replace(tmp, html_path)
print('Updated: %d lines embedded.' % len(t.splitlines()))
