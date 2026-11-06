"""Locations shared by the local-only custom executable builder."""
import os
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
# The decomp source tree (fnv_decomp) is the submodule in decomp/; its tools (msvc.py, build_and_match.py,
# compare.py) are used as they are.
ROOT = REPO / 'decomp'
if str(ROOT / 'tools') not in sys.path:
    sys.path.insert(0, str(ROOT / 'tools'))
# Everything the build produces stays in this repository's ignored .local/ folder, never inside decomp/.
LOCAL = REPO / '.local' / 'custom-exe'
IMAGE = LOCAL / 'input.exe'
TC = Path(os.environ.get('FNV_MSVC9_ROOT', '.')).resolve()


def compiler_environment():
    from msvc import compiler_root
    for compiler in ('sp1','rtm','vc8'):
        compiler_root(compiler)
    root = compiler_root('sp1').resolve()
    env = os.environ.copy()
    env.update(INCLUDE=';'.join(str(root / p) for p in ('VC/include', 'SDK/Include')),
               LIB=';'.join(str(root / p) for p in ('VC/lib', 'SDK/Lib')),
               PATH=str(root / 'VC/bin') + os.pathsep + env.get('PATH', ''))
    return env
