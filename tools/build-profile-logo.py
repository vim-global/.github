"""Rebuild the existing public white presentation panel from the exact approved B2."""

# VG-CATALOGUE-PUBLICATION-PREFLIGHT-1
if __name__ == '__main__':
    import pathlib as _vg_pathlib, runpy as _vg_runpy
    _vg_root = next((_p for _p in _vg_pathlib.Path(__file__).resolve().parents if (_p / 'tools/catalogue-publication-gate/guard.py').is_file()), None)
    if _vg_root is None:
        raise SystemExit('CATALOGUE: shared publication preflight missing')
    _vg_runpy.run_path(str(_vg_root / 'tools/catalogue-publication-gate/guard.py'))['entrypoint'](__file__, _vg_root)

from pathlib import Path
import hashlib,re
root=Path(__file__).resolve().parents[1]
p=root/'profile/assets/primary-transparent.svg'
assert hashlib.sha256(p.read_bytes()).hexdigest()=='0e79e45d5ae4e39bed3f25173ec98e066fd74f6a6450635c644e12f8ceca05e4'
s=p.read_text();body=re.sub(r'^.*?<svg\b[^>]*>','',s,count=1,flags=re.S);body=re.sub(r'</svg>\s*$','',body)
wrapper='<svg xmlns="http://www.w3.org/2000/svg" width="640" height="224" viewBox="0 0 640 224" role="img" aria-label="Vim Global">\n<rect width="640" height="224" fill="white"/>\n<svg x="40" y="32" width="560" height="160" viewBox="0 0 452 147" preserveAspectRatio="xMidYMid meet">'+body+'</svg>\n</svg>\n'
(root/'profile/assets/vim-global.svg').write_text(wrapper)
