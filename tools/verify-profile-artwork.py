#!/usr/bin/env python3
"""Read-only proof of existing approved artwork; never rebuilds or writes UI."""

# VG-CATALOGUE-PUBLICATION-PREFLIGHT-1
if __name__ == '__main__':
    import pathlib as _vg_pathlib, runpy as _vg_runpy
    _vg_root = next((_p for _p in _vg_pathlib.Path(__file__).resolve().parents if (_p / 'tools/catalogue-publication-gate/guard.py').is_file()), None)
    if _vg_root is None:
        raise SystemExit('CATALOGUE: shared publication preflight missing')
    _vg_runpy.run_path(str(_vg_root / 'tools/catalogue-publication-gate/guard.py'))['entrypoint'](__file__, _vg_root)

from pathlib import Path
import hashlib

# Evidence pins for the existing approved assets, not design standards.
APPROVED = {'profile/assets/primary-transparent.svg': '0e79e45d5ae4e39bed3f25173ec98e066fd74f6a6450635c644e12f8ceca05e4', 'profile/assets/vim-global.svg': '6fe1a6bd8d76220771f2f82e11113dc03cc052f1975c6e48550d49957fb0112a'}

def check(root):
    for name, expected in APPROVED.items():
        p = root / name
        if p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            raise ValueError("Approved profile artwork changed: " + name)

if __name__ == "__main__":
    check(Path(__file__).resolve().parents[1])
    print("Approved source and presentation artwork bytes verified; no output generated")
