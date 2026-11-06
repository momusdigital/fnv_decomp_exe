"""Collapse only bindings whose complete original bodies/literals prove identity."""
import hashlib, json
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86 import X86_OP_IMM
from standalone_common import dump,hx


def reconcile_bindings(db,objects,pe,out,accumulate=False):
    from phase2_policy import CoffView
    groups={n:[a for a, in db.execute('SELECT DISTINCT address FROM binding WHERE name=? ORDER BY address',(n,))]
            for n, in db.execute('SELECT name FROM binding GROUP BY name HAVING COUNT(DISTINCT address)>1')}
    literals={};wanted={n for n in groups if n.startswith(('??_C@','__real@','__xmm@'))}
    for path in objects:
        c=None
        if not wanted:break
        # Constants are intrinsic names or independent string COMDATs; use the
        # complete contribution, including all UTF-16 bytes and final terminators.
        c=CoffView(path)
        for t in c.symbols.values():
            n=t['name']
            if n not in wanted or t['section']<=0:continue
            s=c.sections[t['section']]
            if t['value'] or s['relocs'] or s['flags']&0x20:continue
            raw=c.data[s['raw']:s['raw']+s['size']]
            if raw:literals[n]=raw;wanted.remove(n)
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    highlow=dict(pe.relocations())
    def body(a):
        sizes={hi-lo for lo,hi in db.execute("SELECT lo,hi FROM span WHERE lo=? AND kind='function'",(a,))}
        if len(sizes)!=1:return None
        size=next(iter(sizes));raw=bytearray(pe.read(a,size));rels=[]
        for at,t in highlow.items():
            if a<=at and at+4<=a+size:
                raw[at-a:at-a+4]=bytes(4);rels.append((at-a,6,('self',t-a) if a<=t<a+size else ('address',t)))
        for i in md.disasm(pe.read(a,size),a):
            if not (i.group(1) or i.group(2)) or i.imm_size!=4:continue
            dest=next((op.imm&0xffffffff for op in i.operands if op.type==X86_OP_IMM),None)
            if dest is None:continue
            off=i.address-a+i.imm_offset;raw[off:off+4]=bytes(4)
            rels.append((off,20,('self',dest-a) if a<=dest<a+size else ('address',dest)))
        return hashlib.sha256(raw+json.dumps(sorted(rels)).encode()).hexdigest()
    cache={};records=[];equivalent={}
    for n,aa in groups.items():
        proof=None
        try:
            if n in literals and all(pe.read(a,len(literals[n]))==literals[n] for a in aa):
                proof=dict(kind='complete_literal',size=len(literals[n]),sha256=hashlib.sha256(literals[n]).hexdigest())
            elif not n.startswith(('??_C@','__real@','__xmm@')):
                hashes=[]
                for a in aa:
                    if a not in cache:cache[a]=body(a)
                    hashes.append(cache[a])
                if all(hashes) and len(set(hashes))==1:proof=dict(kind='complete_matched_function',sha256=hashes[0])
        except ValueError:pass
        if proof:
            equivalent[n]=set(aa)
            canonical=min(aa)
            units=[u for u, in db.execute('SELECT DISTINCT unit FROM binding WHERE name=?',(n,))]
            db.execute('DELETE FROM binding WHERE name=?',(n,))
            db.executemany('INSERT OR IGNORE INTO binding VALUES (?,?,?)',[(n,canonical,u) for u in units])
            records.append(dict(symbol=n,addresses=list(map(hx,aa)),canonical=hx(canonical),proof=proof))
    for rid,kind,detail in db.execute("SELECT rowid,kind,detail FROM issue WHERE kind='relocation_binding_mismatch'").fetchall():
        d=json.loads(detail);aa=equivalent.get(d['symbol'],set())
        if int(d['recipe'],16) in aa and int(d['observed'],16) in aa:
            db.execute('DELETE FROM issue WHERE rowid=?',(rid,))
    db.commit()
    if accumulate:
        previous=json.loads((out/'binding_equivalences.json').read_text())
        records=previous+records
    dump(out/'binding_equivalences.json',records)
    return dict(collapsed=len(records),remaining=len(groups)-len(records))
