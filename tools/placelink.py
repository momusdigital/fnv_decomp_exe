from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
from config import LOCAL as OUT
import psutil
GIB = 1024 ** 3
RESERVE = 3 * GIB
CHILD_BUDGET = 256 * 1024 ** 2


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    tmp.replace(path)




def load_recipe(tree):
    return json.loads((tree / 'build/units.json').read_text())['units']



class MemoryStatus(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong)] + [
        (name, ctypes.c_ulonglong) for name in
        ('total', 'available', 'page_total', 'page_available', 'virtual_total', 'virtual_available', 'extended')]


def available_memory():
    if os.name == 'nt':
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError('GlobalMemoryStatusEx failed')
        return status.available
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('cannot measure available physical memory')


def compiler_count():
    # Processes may exit between enumeration and reading their name.
    # Windows also reuses PIDs quickly; psutil caches process names on Windows.
    # A reused PID must not inherit the previous compiler's cached name.
    clear_cache=getattr(psutil.process_iter,'cache_clear',None)
    if clear_cache:clear_cache()
    return sum((p.info.get('name') or '').lower() == 'cl.exe'
               for p in psutil.process_iter(['name']))


def input_fingerprint(tree, env):
    """Conservative header invalidation, including newly added/deleted headers.

    Header contents are hashed once per run; changing ANY local header rebuilds
    all units. Source files are hashed per unit. No dependency files are written
    into the read-only source tree and no VC9 flags are added to the recipe.
    """
    h = hashlib.sha256()
    for path in sorted(p for folder in ('include', 'src', 'third_party') for p in (tree / folder).rglob('*')):
        if path.is_file() and path.suffix.lower() in ('.h', '.hpp', '.hxx', '.inl', '.inc'):
            h.update(str(path.relative_to(tree)).encode())
            h.update(path.read_bytes())
    h.update((tree / 'tools/msvc.py').read_bytes())
    for variable in ('CL', '_CL_', 'INCLUDE', 'LIB'):
        h.update((variable + '=' + env.get(variable, '')).encode())
    for variable in ('FNV_MSVC9_ROOT', 'FNV_MSVC9_RTM_ROOT', 'FNV_MSVC8_ROOT'):
        root = Path(env[variable])
        h.update(str(root).encode())
        # Includes and compiler implementation changes invalidate cached objects.
        for folder in ('VC/include', 'SDK/Include', 'VC/bin'):
            for path in sorted((root / folder).rglob('*')):
                if path.is_file():
                    h.update(str(path.relative_to(root)).encode())
                    h.update(path.read_bytes())
    return h.hexdigest()


def build_objects(tree, units, env, jobs, force=False):
    objdir = OUT / 'objs'
    objdir.mkdir(parents=True, exist_ok=True)
    common = input_fingerprint(tree, env)
    tasks, objects, seen = [], [], Counter()
    for i, unit in enumerate(units):
        occurrence = seen[unit['source']]
        seen[unit['source']] += 1
        tag = digest((unit['source'] + ':' + str(occurrence)).encode())[:16]
        stem = re.sub(r'[^a-zA-Z0-9_-]', '_', Path(unit['source']).stem)[:65]
        obj = objdir / ('%04d_%s_%s.obj' % (i, stem, tag))
        meta = obj.with_suffix('.json')
        key = digest(json.dumps(dict(common=common, tree=str(tree), source=unit['source'],
                                     source_hash=digest((tree / unit['source']).read_bytes()),
                                     compiler=unit['compiler'], flags=unit['flags']), sort_keys=True).encode())
        objects.append(obj)
        cached = False
        if not force and obj.exists() and meta.exists():
            try:
                record = json.loads(meta.read_text())
                cached = record['key'] == key and record['object_sha256'] == digest(obj.read_bytes())
            except (ValueError, KeyError, OSError):
                pass
        if not cached:
            tasks.append((unit, obj, meta, key))
    stats = dict(units=len(units), reused=len(units) - len(tasks), compiled=0,
                 max_compiler_processes=0, min_available_bytes=available_memory())
    print('Objects: %d reused, %d to compile; <=%d compilers, 3 GiB RAM reserve.' %
          (stats['reused'], len(tasks), jobs), flush=True)
    children, children_lock, stop_build = set(), threading.Lock(), threading.Event()

    def compile_one(task):
        unit, obj, meta, key = task
        tmp = obj.with_suffix('.building.obj')
        command = [sys.executable, '-B', str(tree / 'tools/msvc.py'), '--compiler', unit['compiler'], '/c', '/nologo']
        command += unit['flags'] + ['/I' + str(tree / 'include'), '/I' + str(tree),
                                    str(tree / unit['source']), '/Fo' + str(tmp)]
        started = time.monotonic()
        with children_lock:
            if stop_build.is_set():
                raise RuntimeError('build stopped for RAM reserve')
            process = subprocess.Popen(command, cwd=tree, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       creationflags=0x08000000 if os.name == 'nt' else 0)
            children.add(process)
        try:
            stdout, stderr = process.communicate()
        finally:
            with children_lock:
                children.discard(process)
        obj.with_suffix('.log').write_bytes(stdout + stderr)
        if process.returncode or not tmp.exists():
            raise RuntimeError('compile failed: %s (see %s)' % (unit['source'], obj.with_suffix('.log')))
        tmp.replace(obj)
        write_json(meta, dict(key=key, source=unit['source'], compiler=unit['compiler'], flags=unit['flags'],
                              object_sha256=digest(obj.read_bytes()), seconds=time.monotonic() - started))
        return obj

    last, blocked, cursor = time.monotonic(), None, 0
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        active = set()
        while cursor < len(tasks) or active:
            free = available_memory()
            stats['min_available_bytes'] = min(stats['min_available_bytes'], free)
            if active and free < RESERVE:
                # Admission alone cannot handle another program suddenly using
                # gigabytes. Stop only our own compiler process trees and resume
                # from committed cache entries on the next run.
                with children_lock:
                    stop_build.set()
                    for child in children:
                        if child.poll() is None:
                            if os.name == 'nt':
                                subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                               creationflags=0x08000000)
                            else:
                                child.kill()
                raise RuntimeError('available physical RAM fell below 3 GiB; stopped this build; rerun to resume')
            # Budget even running children as if they had not allocated yet.
            if cursor < len(tasks) and len(active) < jobs and compiler_count() + len(active) < 8 and free >= RESERVE + (len(active) + 1) * CHILD_BUDGET:
                active.add(pool.submit(compile_one, tasks[cursor]))
                cursor += 1
                stats['max_compiler_processes'] = max(stats['max_compiler_processes'], len(active))
                blocked = None
                continue
            if not active:
                blocked = blocked or time.monotonic()
                if time.monotonic() - blocked > 300:
                    raise RuntimeError('insufficient free RAM for 3 GiB reserve for five minutes; rerun to resume cache')
                time.sleep(0.25)
            else:
                done, active = wait(active, timeout=0.25, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()
                    stats['compiled'] += 1
            if time.monotonic() - last >= 20:
                print('Compile: %d/%d complete, %d running; %.2f GiB free.' %
                      (stats['compiled'], len(tasks), len(active), free / GIB), flush=True)
                last = time.monotonic()
    return objects, stats


def file_offset(pe, address, size):
    rva = address - pe.base
    for start, _, rawsize, offset in pe.sections:
        if start <= rva and rva + size <= start + rawsize:
            return offset + rva - start
    raise ValueError('placement outside file-backed section: 0x%08x + %d' % (address, size))








def imports(pe):
    """IAT slot -> DLL!name, from the original PE import directory."""
    result = {}
    header = struct.unpack_from('<I', pe.data, 0x3c)[0]
    rva, size = struct.unpack_from('<II', pe.data, header + 24 + 96 + 8)
    if not rva or not size:
        return result

    def cstring(address):
        offset = file_offset(pe, address, 1)
        return pe.data[offset:pe.data.index(b'\0', offset)].decode('ascii', errors='replace')

    for i in range(size // 20):
        oft, stamp, chain, name, ft = struct.unpack('<IIIII', pe.read(pe.base + rva + i * 20, 20))
        if not any((oft, stamp, chain, name, ft)):
            break
        dll = cstring(pe.base + name)
        for j in range(65536):
            value = struct.unpack('<I', pe.read(pe.base + (oft or ft) + j * 4, 4))[0]
            if not value:
                break
            label = '#%d' % (value & 0xffff) if value & 0x80000000 else cstring(pe.base + value + 2)
            result[pe.base + ft + j * 4] = dll + '!' + label
    return result


CRT_NAME = re.compile(
    r'^_+(?:(?:memcpy|memmove|memset|memcmp|memchr|strlen|strcpy|strncpy|strcat|strncat|strcmp|strncmp|'
    r'stricmp|strnicmp|strchr|strrchr|strstr|strtok|strtol|strtoul|strtod|atoi|atol|atof|'
    r'wcslen|wcscpy|wcsncpy|wcscmp|wcsncmp|malloc|calloc|realloc|free|new|delete|'
    r'printf|fprintf|sprintf|snprintf|vsprintf|vsnprintf|sscanf|fopen|fclose|fread|fwrite|'
    r'fseek|ftell|fflush|fgetc|fputc|fgets|fputs|puts|abort|exit|atexit|onexit|'
    r'qsort|bsearch|rand|srand|time|clock|localtime|gmtime|mktime|setlocale|localeconv|'
    r'getenv|putenv|errno|assert|purecall|initterm|initterm_e|amsg_exit|'
    r'ftol|ftol2|ftol2_sse|allmul|alldiv|aulldiv|allrem|aullrem|allshl|allshr|aullshr|'
    r'CIacos|CIasin|CIatan|CIatan2|CIcos|CIcosh|CIexp|CIfmod|CIlog|CIlog10|CIpow|CIsin|CIsinh|CIsqrt|CItan|CItanh)'
    r'(?:@\d+)?$|(?:CxxFrameHandler|EH_prolog|EH_epilog|SEH_prolog|SEH_epilog|'
    r'except_handler|security_check_cookie|security_init_cookie|report_gsfailure|alloca_probe|chkstk))')
