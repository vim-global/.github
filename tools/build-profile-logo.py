"""Rebuild the existing public white presentation panel from the exact approved B2."""
from pathlib import Path
import hashlib,re
root=Path(__file__).resolve().parents[1]
p=root/'profile/assets/primary-transparent.svg'
assert hashlib.sha256(p.read_bytes()).hexdigest()=='0e79e45d5ae4e39bed3f25173ec98e066fd74f6a6450635c644e12f8ceca05e4'
s=p.read_text();body=re.sub(r'^.*?<svg\b[^>]*>','',s,count=1,flags=re.S);body=re.sub(r'</svg>\s*$','',body)
wrapper='<svg xmlns="http://www.w3.org/2000/svg" width="640" height="224" viewBox="0 0 640 224" role="img" aria-label="Vim Global">\n<rect width="640" height="224" fill="white"/>\n<svg x="40" y="32" width="560" height="160" viewBox="0 0 452 147" preserveAspectRatio="xMidYMid meet">'+body+'</svg>\n</svg>\n'
(root/'profile/assets/vim-global.svg').write_text(wrapper)
