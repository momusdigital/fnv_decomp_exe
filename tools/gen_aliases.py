import ctypes
import json
import re
import struct
from pathlib import Path

from standalone_common import COFF, OUT, database, dump, hx, label, spans


def weak_aliases(pairs,path):
    """Symbol-only COFF weak SEARCH_ALIAS records, without directive parsing."""
    pairs=[(a,b) for a,b in pairs if a!=b];strings=bytearray(bytes(4));symbols=bytearray()
    targets={n:i for i,n in enumerate(sorted({b for a,b in pairs}))}
    def rawname(n):
        b=n.encode('ascii')
        if len(b)<=8:return b.ljust(8,b'\0')
        off=len(strings);strings.extend(b+b'\0');return struct.pack('<II',0,off)
    for name in targets:
        symbols.extend(struct.pack('<8sIhHBB',rawname(name),0,0,0,2,0))
    for name,target in pairs:
        symbols.extend(struct.pack('<8sIhHBB',rawname(name),0,0,0,105,1))
        symbols.extend(struct.pack('<II10s',targets[target],3,bytes(10)))
    struct.pack_into('<I',strings,0,len(strings))
    Path(path).write_bytes(struct.pack('<HHIIIHH',0x14c,0,0,20,len(symbols)//18,0,0)+symbols+strings)


def undecorate(name):
    if not name.startswith('?'):
        return name
    buf = ctypes.create_string_buffer(32768)
    f = ctypes.windll.dbghelp.UnDecorateSymbolName
    f.argtypes = [ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint,ctypes.c_uint]
    if not f(name.encode('ascii'),buf,len(buf),0):
        return name
    return buf.value.decode('ascii',errors='replace')


def split_types(text):
    out, start, depth = [], 0, 0
    for i,c in enumerate(text):
        if c in '<([': depth += 1
        elif c in '>)]': depth -= 1
        elif c == ',' and depth == 0:
            out.append(text[start:i].strip()); start = i+1
    out.append(text[start:].strip())
    return [] if out == ['void'] or out == [''] else out


def slot(typ):
    # x86 arguments occupy at least four bytes. By-value user aggregates cannot
    # be sized from their decorated name, so explicitly remain unverified.
    if '*' in typ or '&' in typ or typ.startswith('enum '): return 4
    typ = re.sub(r'\b(const|volatile|signed|unsigned)\b','',typ)
    typ = ' '.join(typ.split())
    if typ in ('bool','char','short','short int','int','long','long int','float','wchar_t'): return 4
    if typ in ('double','long double','__int64'): return 8
    return None


def abi(name):
    if not name.startswith('?'):
        m = re.fullmatch(r'([_@]).+@(\d+)',name)
        if m:
            total = int(m[2]); cc = 'stdcall' if m[1]=='_' else 'fastcall'
            # Fastcall decoration includes register arguments; without parameter
            # types the exact register/stack split is not recoverable.
            return dict(convention=cc,cleanup=total if cc=='stdcall' else None,decoded=name,
                        reason=None if cc=='stdcall' else 'fastcall parameter types unavailable')
        if name.startswith('_'):
            return dict(convention='cdecl',cleanup=0,decoded=name,reason=None)
        return dict(convention=None,cleanup=None,decoded=name,reason='undecorated ABI unavailable')
    text = undecorate(name)
    conventions=re.findall(r'__(cdecl|stdcall|thiscall|fastcall|vectorcall)\b',text)
    if len(conventions)!=1:
        return dict(convention=None,cleanup=None,decoded=text,reason='nested or unrecognized function ABI')
    m = re.search(r'__(cdecl|stdcall|thiscall|fastcall|vectorcall)\b',text)
    if not m or not text.endswith(')') and ') const' not in text and ') volatile' not in text:
        return dict(convention=None,cleanup=None,decoded=text,reason='function decoration unavailable')
    cc = m[1]
    # Locate the outer function parameter list by walking backwards through its
    # balanced parentheses, not a regex that misreads function-pointer arguments.
    end = text.rfind(')'); depth=1; start=end-1
    while start>=0:
        if text[start]==')': depth+=1
        elif text[start]=='(':
            depth-=1
            if depth==0: break
        start-=1
    args = split_types(text[start+1:end]) if start>=0 else ['<unknown>']
    sizes = [slot(t) for t in args]
    reason = None
    if cc=='cdecl' or '...' in args:
        cleanup=0
    elif any(n is None for n in sizes):
        cleanup=None; reason='by-value aggregate or unrecognized parameter size'
    else:
        cleanup=sum(sizes)
        if cc=='fastcall':
            eligible=sum(n==4 and ('*' in t or '&' in t or not t.startswith(('struct ','class '))) for n,t in zip(sizes,args))
            cleanup-=4*min(2,eligible)
    # A by-value aggregate return may introduce a hidden return-storage argument.
    prefix=text[:m.start()]
    hidden=bool(re.search(r'\b(class|struct|union)\b',prefix) and '*' not in prefix and '&' not in prefix)
    if hidden:
        cleanup=None; reason='aggregate return requires hidden-argument ABI evidence'
    return dict(convention=cc,cleanup=cleanup,decoded=text,reason=reason)


def compatible(a,b):
    aa,bb=abi(a),abi(b)
    if aa['convention'] is None or bb['convention'] is None or aa['cleanup'] is None or bb['cleanup'] is None:
        return 'unverified',aa,bb
    if (aa['convention'],aa['cleanup']) != (bb['convention'],bb['cleanup']):
        return 'mismatch',aa,bb
    return 'ok',aa,bb


def generate(db, out):
    out=Path(out); counts={}; directives=[]
    _,find=spans(db)
    canonical_imports={n for n, in db.execute('SELECT DISTINCT symbol FROM import')}
    db.execute('DELETE FROM alias')
    query='''SELECT r.name, MIN(b.address), COUNT(DISTINCT b.address)
             FROM reference r LEFT JOIN binding b ON b.name=r.name
             WHERE NOT EXISTS(SELECT 1 FROM definition d WHERE d.name=r.name)
               AND NOT EXISTS(SELECT 1 FROM resolved_weak w WHERE w.name=r.name)
             GROUP BY r.name ORDER BY r.name'''
    with (out/'alias_checks.jsonl').open('w',encoding='utf-8') as log:
        for name,address,n in db.execute(query):
            detail={}; target=None
            if name in canonical_imports:
                # A reconstructed stand-in can reuse the native name of a
                # different import. Its matched operands are redirected before
                # linking; it must never override the linker's real IAT symbol.
                target=name;status='ok_import'
                detail=dict(native_iat_identity='reserved canonical import symbol',
                            source_binding_addresses=[hx(a) for a, in db.execute('SELECT DISTINCT address FROM binding WHERE name=?',(name,))])
            elif n!=1:
                status='conflicting_bindings' if n else 'unbound'
            elif db.execute('SELECT 1 FROM import WHERE address=?',(address,)).fetchone():
                target=db.execute('SELECT symbol FROM import WHERE address=?',(address,)).fetchone()[0]
                status='ok_import'
                if name.startswith('__imp_') and target.startswith('__imp_'):
                    aa,bb=abi(name[6:]),abi(target[6:])
                    if bb['convention'] in ('stdcall','fastcall') and aa['convention'] and aa['cleanup'] is not None and bb['cleanup'] is not None:
                        status,aa,bb=compatible(name[6:],target[6:])
                        detail=dict(requested_abi=aa,implementation_abi=bb)
            else:
                target=label(address)
                owner=find(address)
                s=db.execute('SELECT reason FROM address WHERE address=?',(address,)).fetchone()
                if not s or db.execute('SELECT 1 FROM issue WHERE kind=? AND detail LIKE ?',
                    ('unmapped_address','%"address": "'+hx(address)+'"%')).fetchone():
                    status='unmapped'
                elif owner and owner[6]=='function' and address==owner[0]:
                    implementation=owner[5]
                    status,aa,bb=compatible(name,implementation)
                    detail=dict(implementation=implementation,requested_abi=aa,implementation_abi=bb)
                elif s[0].startswith('data') or s[0] in ('tls','absolute_constant'):
                    status='ok_data'
                else:
                    # Original runtime/gap entries have no compiled declaration.
                    # Emitting a pointer alias is safe only after the generator's
                    # runtime ABI verifier has associated a decoded return path.
                    check=db.execute('SELECT detail FROM issue WHERE kind=? AND detail LIKE ?',
                                     ('runtime_abi','%"address": "'+hx(address)+'"%')).fetchone()
                    aa=abi(name)
                    if check:
                        observed=json.loads(check[0]); cleanup=observed['cleanup']
                        bb=observed.get('implementation_abi')
                        if bb is None:status='unverified_runtime_abi'
                        else:status='ok' if aa['cleanup']==cleanup and (aa['convention'],aa['cleanup'])==(bb['convention'],bb['cleanup']) else 'mismatch'
                        detail=dict(requested_abi=aa,observed_cleanup=cleanup,implementation=observed.get('implementation'),implementation_abi=bb)
                    else:
                        status='unverified_runtime_abi'; detail=dict(requested_abi=aa)
            # A matched caller's bytes, rather than its reconstructed prototype,
            # prove the target ABI. Names used only in unmatched compiler copies
            # have no such proof and must disappear under /OPT:REF or stay errors.
            if target and status in ('mismatch','unverified','unverified_runtime_abi','ok'):
                proved=db.execute('SELECT 1 FROM matched_reference WHERE name=? LIMIT 1',(name,)).fetchone()
                if proved:
                    if not status.startswith('ok'):
                        detail['abi_warning']=status
                        status='ok_address'
                else:
                    detail['abi_warning']=status
                    status='unproved_copy_reference'
                    target=None
            counts[status]=counts.get(status,0)+1
            db.execute('INSERT INTO alias VALUES (?,?,?,?)',
                       (name,target,status,json.dumps(detail)))
            if status.startswith('ok'):
                if any(c.isspace() or c in '=\"' for c in name+target):
                    raise ValueError('unsupported linker directive symbol: '+name)
                if name!=target:directives.append('/alternatename:'+name+'='+target)
            log.write(json.dumps(dict(symbol=name,address=hx(address) if address else None,
                                      target=target,status=status,**detail))+'\n')
    c=COFF(); c.section('.drectve',(' '+' '.join(directives)+' ').encode('ascii'),0x100a00)
    c.write(out/'aliases_directives.obj')
    weak_aliases(db.execute("SELECT name,target FROM alias WHERE status LIKE 'ok%'"),out/'aliases.obj')
    db.commit()
    dump(out/'aliases_report.json',dict(counts=counts,emitted=len(directives),
        policy='Matched recipe references bind by address; decorated ABI checks are warnings only. Unmatched-only code has no address-alias proof.',
        format='COFF weak externals, SEARCH_ALIAS=3; directive equivalent saved separately'))
    return counts
