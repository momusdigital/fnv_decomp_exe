import json
import re
import sqlite3
import struct
import sys
import time
from bisect import bisect_right
from pathlib import Path

import placelink as place

from config import ROOT as TREE, LOCAL as OUT, IMAGE, TC
BASE = TREE



def hx(n):
    return '0x%08x' % n


def label(n):
    return '_fnv_va_%08x' % n


def dump(path, value):
    place.write_json(Path(path), value)


def rows(path):
    """Stream a JSON array, including pretty-printed and >1 GB inventories."""
    dec = json.JSONDecoder()
    with Path(path).open(encoding='utf-8-sig') as stream:
        buf, ended = '', False
        while True:
            buf = buf.lstrip(' \r\n\t[,')
            if buf.startswith(']'):
                return
            try:
                value, end = dec.raw_decode(buf)
            except ValueError:
                if ended:
                    if buf.strip():
                        raise ValueError('incomplete JSON array: ' + str(path))
                    return
                chunk = stream.read(65536)
                ended = not chunk
                buf += chunk
                continue
            yield value
            buf = buf[end:]


def reserve(extra=64 * 1024**2, timeout=300):
    start = time.monotonic()
    while place.available_memory() < place.RESERVE + extra:
        if time.monotonic() - start >= timeout:
            raise RuntimeError('3 GiB free RAM reserve unavailable; rerun to resume')
        time.sleep(.25)


def database(path=OUT / 'state.sqlite'):
    db = sqlite3.connect(path)
    db.execute('PRAGMA cache_size=-8192')
    db.execute('PRAGMA temp_store=FILE')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS binding(name TEXT, address INTEGER, unit INTEGER,
                                        PRIMARY KEY(name,address,unit));
      CREATE INDEX IF NOT EXISTS bind_address ON binding(address);
      CREATE TABLE IF NOT EXISTS definition(name TEXT, unit INTEGER, section INTEGER,
           offset INTEGER, comdat INTEGER, code INTEGER, PRIMARY KEY(name,unit,section,offset));
      CREATE TABLE IF NOT EXISTS reference(name TEXT, unit INTEGER,
                                          PRIMARY KEY(name,unit));
      CREATE TABLE IF NOT EXISTS weak(name TEXT, fallback TEXT, search INTEGER, unit INTEGER);
      CREATE TABLE IF NOT EXISTS resolved_weak(name TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS span(lo INTEGER, hi INTEGER, unit INTEGER,
                      section INTEGER, offset INTEGER, name TEXT, kind TEXT);
      CREATE INDEX IF NOT EXISTS span_lo ON span(lo);
      CREATE INDEX IF NOT EXISTS span_object_section ON span(unit,section,offset);
      CREATE TABLE IF NOT EXISTS address(address INTEGER PRIMARY KEY, reason TEXT);
      CREATE TABLE IF NOT EXISTS import(address INTEGER PRIMARY KEY, dll TEXT,
                      export TEXT, symbol TEXT);
      CREATE TABLE IF NOT EXISTS issue(kind TEXT, detail TEXT);
      CREATE TABLE IF NOT EXISTS alias(name TEXT PRIMARY KEY, target TEXT, status TEXT, detail TEXT);
    ''')
    return db


class PE:
    def __init__(self, path):
        self.path = Path(path)
        sys.path.insert(0, str(TREE / 'tools'))
        from compare import Pe
        self.pe = Pe(path)
        self.data, self.base = self.pe.data, self.pe.base
        self.header = struct.unpack_from('<I', self.data, 0x3c)[0]
        self.opt = self.header + 24
        self.entry = self.base + struct.unpack_from('<I', self.data, self.opt + 16)[0]
        self.characteristics = struct.unpack_from('<H', self.data, self.header + 22)[0]
        self.sections = [dict(name=name, lo=self.base+rva, hi=self.base+rva+max(vs,rs),
                              virtual_size=vs, raw_size=rs, raw=raw)
                         for name, (rva,vs,rs,raw) in zip(self.pe.names,self.pe.sections)]
        self.header_size=struct.unpack_from('<I',self.data,self.opt+60)[0]
        self.image_size=struct.unpack_from('<I',self.data,self.opt+56)[0]
        for s in self.sections:s['pagehi']=(s['hi']+4095)&~4095

    def read(self, a, n):
        s = self.section(a)
        if s is None or a+n > s['pagehi']:
            raise ValueError('unmapped image range: %s + %d' % (hx(a), n))
        take = max(0, min(n, s['lo']+s['raw_size']-a))
        off = s['raw']+a-s['lo']
        return self.data[off:off+take] + bytes(n-take)

    def section(self, a):
        return next((s for s in self.sections if s['lo'] <= a < s['pagehi']), None)

    def directory(self, i):
        a, n = struct.unpack_from('<II', self.data, self.opt+96+i*8)
        return (self.base+a if a else 0), n

    def relocations(self):
        start, n = self.directory(5)
        pos = 0
        while pos < n:
            page, size = struct.unpack('<II', self.read(start+pos,8))
            if size < 8 or pos+size > n:
                raise ValueError('invalid base relocation block')
            for (item,) in struct.iter_unpack('<H', self.read(start+pos+8,size-8)):
                kind, off = item >> 12, item & 4095
                if kind == 0:
                    continue
                if kind != 3:
                    raise ValueError('unsupported base relocation type: %d' % kind)
                a = self.base+page+off
                yield a, struct.unpack('<I',self.read(a,4))[0]
            pos += size

    def imports(self):
        return place.imports(self.pe)


class COFF:
    """Small i386 COFF writer; supports relocation overflow, BSS and long names."""
    def __init__(self):
        self.sections, self.symbols, self.names = [], [], {}

    def section(self, name, data=b'', flags=0x40300040, size=None):
        self.sections.append(dict(name=name, data=bytearray(data), flags=flags,
                                  size=len(data) if size is None else size, relocs=[]))
        return len(self.sections)

    def symbol(self, name, section=0, value=0, typ=0, storage=2):
        if name in self.names:
            i = self.names[name]
            old = self.symbols[i]
            if section and old[1] and old[1:] != (section,value,typ,storage):
                raise ValueError('conflicting generated COFF definition: '+name)
            if section:
                self.symbols[i] = (name,section,value,typ,storage)
            return i
        i = len(self.symbols)
        self.names[name] = i
        self.symbols.append((name,section,value,typ,storage))
        return i

    def reloc(self, sn, off, name, kind, addend=0):
        sec = self.sections[sn-1]
        if not 0 <= off <= len(sec['data'])-4:
            raise ValueError('relocation outside generated section')
        struct.pack_into('<I',sec['data'],off,addend & 0xffffffff)
        sec['relocs'].append((off,self.symbol(name),kind))

    def write(self, path):
        if len(self.sections) > 32767:
            raise ValueError('too many sections for VC9 COFF')
        strings = bytearray(b'\0'*4)
        def name(n, section=False):
            raw = n.encode('ascii')
            if len(raw) <= 8:
                return raw.ljust(8,b'\0')
            off = len(strings)
            strings.extend(raw+b'\0')
            return (('/%d'%off).encode().ljust(8,b'\0') if section
                    else struct.pack('<II',0,off))
        headers, payload = [], bytearray()
        base = 20+40*len(self.sections)
        for sec in self.sections:
            raw = base+len(payload) if sec['data'] else 0
            payload.extend(sec['data'])
            rr = sec['relocs']
            rp = base+len(payload) if rr else 0
            flags = sec['flags']
            if len(rr) >= 65535:
                flags |= 0x1000000
                payload.extend(struct.pack('<IIH',len(rr)+1,0,0))
            for r in rr:
                payload.extend(struct.pack('<IIH',*r))
            headers.append(struct.pack('<8sIIIIIIHHI',name(sec['name'],True),0,0,
                sec['size'],raw,rp,0,min(len(rr),65535),0,flags))
        symptr = base+len(payload)
        syms = b''.join(struct.pack('<8sIhHBB',name(n),v,s,t,c,0)
                        for n,s,v,t,c in self.symbols)
        struct.pack_into('<I',strings,0,len(strings))
        with Path(path).open('wb') as f:
            f.write(struct.pack('<HHIIIHH',0x14c,len(headers),0,symptr,len(self.symbols),0,0))
            f.write(b''.join(headers)); f.write(payload); f.write(syms); f.write(strings)


def append_symbols(source, output, symbols):
    """Append external interior labels without changing compiler bytes/relocs/aux indexes."""
    data = bytearray(Path(source).read_bytes())
    ptr,count = struct.unpack_from('<II',data,8)
    end = ptr+count*18
    strings = bytearray(data[end:])
    if len(strings) < 4 or struct.unpack_from('<I',strings)[0] != len(strings):
        raise ValueError('unexpected trailing data after COFF string table')
    extra = bytearray()
    for n,s,v in symbols:
        nb = n.encode('ascii')
        if len(nb) > 8:
            raw = struct.pack('<II',0,len(strings)); strings.extend(nb+b'\0')
        else:
            raw = nb.ljust(8,b'\0')
        extra.extend(struct.pack('<8sIhHBB',raw,v,s,0,2,0))
    struct.pack_into('<I',strings,0,len(strings))
    struct.pack_into('<I',data,12,count+len(symbols))
    Path(output).write_bytes(data[:end]+extra+strings)


def spans(db):
    """Choose an actual compiler owner of each covered byte; no nearest-function guesses."""
    ss = list(db.execute('SELECT lo,hi,unit,section,offset,name,kind FROM span ORDER BY lo,hi DESC,unit DESC'))
    starts = [s[0] for s in ss]
    # Most functions are disjoint. Prefix maximum handles overlapping identical
    # entries without accidentally missing a containing earlier span.
    maxima, high = [], 0
    for s in ss:
        high = max(high,s[1]); maxima.append(high)
    def find(a):
        i = bisect_right(starts,a)-1
        while i >= 0 and maxima[i] > a:
            if ss[i][0] <= a < ss[i][1]:
                return ss[i]
            i -= 1
        return None
    return ss, find


def issue(db, kind, **detail):
    db.execute('INSERT INTO issue VALUES (?,?)',(kind,json.dumps(detail)))


def archive_symbols(path):
    """Read the big-endian first linker member of a Microsoft COFF archive."""
    with Path(path).open('rb') as f:
        if f.read(8)!=b'!<arch>\n':raise ValueError('not a COFF archive: '+str(path))
        while True:
            header=f.read(60)
            if len(header)!=60:raise ValueError('archive has no symbol index: '+str(path))
            size=int(header[48:58]);name=header[:16].decode('ascii').strip()
            data=f.read(size)
            if size&1:f.read(1)
            if name=='/':
                count=struct.unpack_from('>I',data)[0]
                start=4+4*count
                if start>len(data):raise ValueError('invalid COFF archive index')
                names=data[start:].split(b'\0')
                if len(names)<count:raise ValueError('truncated COFF archive index')
                return {n.decode('ascii') for n in names[:count]}


def archive_imports(path):
    """(DLL, export-name-or-ordinal) -> __imp_ symbol for short import members."""
    result={}
    with Path(path).open('rb') as f:
        if f.read(8)!=b'!<arch>\n':raise ValueError('not a COFF archive')
        while header:=f.read(60):
            if len(header)!=60:raise ValueError('truncated archive header')
            size=int(header[48:58]);data=f.read(size)
            if size&1:f.read(1)
            if len(data)<20 or data[:4]!=b'\0\0\xff\xff':continue
            sig1,sig2,version,machine,stamp,length,hint,flags=struct.unpack_from('<HHHHIIHH',data)
            if machine!=0x14c or length>len(data)-20:continue
            parts=data[20:20+length].split(b'\0')
            if len(parts)<3:continue
            name,dll=parts[0].decode('ascii'),parts[1].decode('ascii')
            kind=(flags>>2)&7
            if kind==0:export='#'+str(hint)
            elif kind==1:export=name
            elif kind==2:export=name[1:] if name[:1] in '_@?' else name
            elif kind==3:export=re.sub(r'@\d+$','',name[1:] if name[:1] in '_@?' else name)
            elif kind==4 and len(parts)>3:export=parts[2].decode('ascii')
            else:continue
            result[dll.lower(),export]='__imp_'+name
    return result
