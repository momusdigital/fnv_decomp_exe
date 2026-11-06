"""Generate relocatable image parts from a locally opened, read-only game EXE.

This module never copies PE headers or the original .reloc to the output. Native
link.exe owns all final addresses, imports, directories and base relocations.
"""
import json
import struct
from bisect import bisect_right
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

from standalone_common import (BASE, COFF, IMAGE, OUT, PE, database, dump, hx,
                               issue, label, spans)


def merged(intervals):
    out=[]
    for a,b in sorted(intervals):
        if out and a<=out[-1][1]: out[-1][1]=max(out[-1][1],b)
        else: out.append([a,b])
    return out


def gaps(a,b,covered):
    pos=a
    for lo,hi in covered:
        if hi<=a or lo>=b: continue
        if pos<lo: yield pos,lo
        pos=max(pos,hi)
    if pos<b: yield pos,b


class Generator:
    def __init__(self,db,image,out):
        self.db,self.pe,self.out=db,PE(image),Path(out)
        self.owner_spans,self.owner=spans(db)
        self.covered=merged((s[0],s[1]) for s in self.owner_spans)
        self.highlow=dict(self.pe.relocations())
        self.counts=Counter()
        self.md=Cs(CS_ARCH_X86,CS_MODE_32);self.md.detail=True
        self.parts=[]
        self.targets=set()

    def target(self,a,reason):
        self.targets.add(a)
        self.db.execute('INSERT OR IGNORE INTO address VALUES (?,?)',(a,reason))
        return label(a)

    def pointer(self,c,sn,off,target,kind=6):
        if self.pe.base<=target<self.pe.base+self.pe.header_size:
            # __ImageBase is linker-owned, so these are relocations to the new
            # image headers, rather than fixed references to the old base.
            c.reloc(sn,off,'___ImageBase',kind,target-self.pe.base)
            self.target(target,'image_header')
            if target-self.pe.base>=self.pe.header:
                issue(self.db,'header_interior_semantics',address=hx(target),
                      reason='PE-header interior needs a field mapping after native link')
            return
        imported=self.db.execute('SELECT symbol FROM import WHERE address=?',(target,)).fetchone()
        name=imported[0] if imported else self.target(target,'pointer_target')
        c.reloc(sn,off,name,kind)

    def data(self):
        c=COFF();owned=[];biases={}
        # Reconciliation is deliberately conservative. The inventory's coverage
        # union is conditional, so never subtract stale inventory-owned bytes.
        # Verified current compiler sections are recorded by standalone.py.
        for detail, in self.db.execute("SELECT detail FROM issue WHERE kind='compiler_data_owner'"):
            d=json.loads(detail);owned.append((d['lo'],d['hi']))
        owned=merged(owned)
        for s in self.pe.sections:
            if s['name'] not in ('.rdata','.data','.tls','CONST'):continue
            # Only the virtual extent is semantic. Raw section alignment bytes
            # may be addressed by recipes; include them when such a label exists.
            end=s['lo']+s['virtual_size']
            bound=self.db.execute('SELECT MAX(address) FROM address WHERE address>=? AND address<?',
                                  (end,s['pagehi'])).fetchone()[0]
            if bound is not None:end=s['pagehi']
            for lo,hi in gaps(s['lo'],end,owned):
                # Keep zero fill as uninitialized storage, including a mixed
                # .data section's zero-fill tail.
                rawend=min(hi,s['lo']+s['raw_size'])
                cuts=sorted({lo,hi,max(lo,rawend)})
                for a,b in zip(cuts,cuts[1:]):
                    if a==b:continue
                    bss=a>=s['lo']+s['raw_size']
                    name=s['name'] if s['name']!='.data' or not bss else '.bss'
                    # SSE aligned loads require the original VA modulo 16,
                    # including fragments that start inside an aligned block.
                    bias=a & 15
                    flags=(0xc0500080 if bss else (0xc0500040 if name in ('.data','.tls') else 0x40500040))
                    sn=c.section(name,b'' if bss else bytes(bias)+self.pe.read(a,b-a),flags,size=b-a+bias)
                    biases[sn]=bias
                    self.counts['data_alignment_padding_bytes']+=bias
                    self.parts.append((a,b,'data',len(c.sections)))
                    self.db.execute("UPDATE address SET reason=? WHERE address>=? AND address<?",
                                    ('tls' if name=='.tls' else 'data',a,b))
                    self.counts['zero_fill_bytes' if bss else 'initialized_data_bytes']+=b-a
                    for at,target in self.highlow.items():
                        if a<=at<b:
                            if at+4>b:raise ValueError('HIGHLOW crosses generated boundary: '+hx(at))
                            if bss:raise ValueError('HIGHLOW in zero-fill storage')
                            self.pointer(c,sn,at-a+bias,target); self.counts['data_DIR32']+=1
        self.define_labels(c,self.parts,biases)
        for a,reason in self.db.execute("SELECT address,reason FROM address WHERE reason='absolute_constant'"):
            c.symbol(label(a),-1,a)
        c.section('.drectve',(' /alternatename:'+label(self.pe.base)+'=___ImageBase ').encode('ascii'),0x100a00)
        tls,size=self.pe.directory(9)
        if tls:
            part=next(((a,sn) for a,b,k,sn in self.parts if a<=tls and tls+24<=b),None)
            if part is None:raise ValueError('TLS directory not generated or owned')
            c.symbol('__tls_used',part[1],tls-part[0]+biases[part[1]])
        c.write(self.out/'image_data.obj')

    def define_labels(self,c,parts,biases=None):
        for a,b,kind,sn in parts:
            for address, in self.db.execute('SELECT address FROM address WHERE address>=? AND address<?',(a,b)):
                if self.db.execute('SELECT 1 FROM import WHERE address=?',(address,)).fetchone():continue
                c.symbol(label(address),sn,address-a+(biases or {}).get(sn,0))
                self.counts['defined_'+kind+'_labels']+=1

    def discover(self):
        # Every recipe-bound address and every HIGHLOW target has its own label.
        self.db.execute('INSERT OR IGNORE INTO address SELECT DISTINCT address,\'recipe\' FROM binding')
        self.db.execute("UPDATE address SET reason='absolute_constant' WHERE address>=0 AND address<?",(self.pe.base,))
        for a,t in self.highlow.items():
            self.target(t,'HIGHLOW_target')
        self.target(self.pe.entry,'entry')
        tls,size=self.pe.directory(9)
        self.tls_callbacks=[]
        if tls:
            start,end,index,callbacks,zero,chars=struct.unpack('<IIIIII',self.pe.read(tls,24))
            self.target(tls,'TLS_directory')
            for a in (start,end,index,callbacks):
                if a:self.target(a,'tls')
            if callbacks:
                for i in range(65536):
                    cb=struct.unpack('<I',self.pe.read(callbacks+4*i,4))[0]
                    if not cb:break
                    self.target(cb,'TLS_callback');self.tls_callbacks.append(cb)
                else:raise ValueError('TLS callbacks not terminated')
        self.db.commit()

    def code(self):
        s=next(s for s in self.pe.sections if s['name']=='.text')
        allgaps=list(gaps(s['lo'],s['lo']+s['virtual_size'],self.covered))
        # Preserve all bytes of the out-of-scope ranges, including inline data.
        # Padding ranges share one packed section; live ranges get their own
        # sections so boundary fallthrough can acquire an explicit jump.
        c=COFF();parts=[];relbranches=[];shorts=[];unmapped=[];runtime={}
        branch_trace=[]
        highlow_sites=sorted(self.highlow)
        for lo,hi in allgaps:
            data=self.pe.read(lo,hi-lo)
            if all(x in (0xcc,0x90) for x in data):
                # Unreferenced padding has no program identity and can vanish.
                needed=self.db.execute('SELECT 1 FROM address WHERE address>=? AND address<? LIMIT 1',(lo,hi)).fetchone()
                if not needed:
                    self.counts['omitted_padding_bytes']+=hi-lo;continue
            sn=c.section('.text',data,0x60500020)
            parts.append((lo,hi,'code',sn));self.counts['generated_code_bytes']+=hi-lo
            self.target(lo,'generated_code')
            for site in highlow_sites[bisect_right(highlow_sites,lo-1):bisect_right(highlow_sites,hi-1)]:
                if site+4>hi:raise ValueError('HIGHLOW crosses code range: '+hx(site))
                self.pointer(c,sn,site-lo,self.highlow[site]);self.counts['code_DIR32']+=1
            if all(x in (0xcc,0x90) for x in data):continue
            # Decode every range linearly with capstone's skipdata. Relocation
            # sites and jump-table bytes are excluded. Reachability verification
            # below records undecodable tails rather than assuming coverage.
            self.md.skipdata=True
            decoded={i.address:i for i in self.md.disasm(data,lo)}
            seeds={lo}|{a for (a,) in self.db.execute(
                'SELECT address FROM address WHERE address>=? AND address<?',(lo,hi))}
            # A label can name inline data as well as code. In particular a
            # switch-table address is itself a HIGHLOW site, not an instruction
            # entry. Starting a decoder there can mistake a SHR ModR/M byte for
            # E9 and manufacture a branch outside the entire executable.
            pointer_bytes={h+j for h in highlow_sites[bisect_right(highlow_sites,lo-4):bisect_right(highlow_sites,hi-1)] for j in range(4)}
            seeds={a for a in seeds if a not in pointer_bytes}
            todo=[(a,a) for a in seeds];visited=set();returns=set();boundary=False
            while todo:
                a,root=todo.pop()
                while lo<=a<hi and a not in visited:
                    i=decoded.get(a)
                    if i is None or not i.id:
                        i=next(self.md.disasm(data[a-lo:],a,count=1),None)
                    if not i or not i.id:break
                    visited.add(a)
                    if i.group(1) or i.group(2):
                        dest=next((op.imm & 0xffffffff for op in i.operands if op.type==X86_OP_IMM),None)
                        if dest is not None:
                            if lo<=dest<hi:todo.append((dest,root))
                            if not lo<=dest<hi:
                                if i.imm_size==4 and (i.bytes[0] in (0xe8,0xe9) or bytes(i.bytes[:1])==b'\x0f'):
                                    off=a-lo+i.imm_offset
                                    if not any(a+i.imm_offset<=h<a+i.imm_offset+4 for h in highlow_sites[bisect_right(highlow_sites,a-1):bisect_right(highlow_sites,a+i.size)]):
                                        relbranches.append((sn,off,dest,a,i.mnemonic))
                                        branch_trace.append(dict(address=hx(a),target=hx(dest),root=hx(root),instruction=i.mnemonic))
                                elif i.imm_size in (1,2):
                                    shorts.append(dict(address=hx(a),target=hx(dest),instruction=i.mnemonic))
                    if i.group(3):
                        returns.add(i.operands[0].imm if i.operands else 0);break
                    if i.mnemonic in ('jmp','ljmp','int3','ud2','hlt'):break
                    a+=i.size
                    if a==hi:boundary=True
            # A generated fragment that can fall into a compiler-owned next byte
            # gets an explicit relocatable E9 continuation, never original VA padding.
            if boundary:
                off=len(c.sections[sn-1]['data'])+1
                c.sections[sn-1]['data'].extend(b'\xe9\0\0\0\0')
                c.sections[sn-1]['size']+=5
                self.pointer(c,sn,off,hi,20);self.counts['fallthrough_jumps']+=1
            # Verify callee cleanup separately at each named runtime entry.
            for entry in seeds:
                if not self.db.execute('SELECT 1 FROM binding WHERE address=?',(entry,)).fetchone():continue
                clean=self.return_cleanup(entry,lo,hi,decoded)
                if clean is not None:
                    runtime[entry]=clean
            self.counts['decoded_live_instructions']+=len(visited)
            self.counts['generated_ranges']+=1
        for sn,off,dest,a,mnem in relbranches:
            self.pointer(c,sn,off,dest,20);self.counts['code_REL32']+=1
        for d in shorts:issue(self.db,'external_short_branch',**d)
        from gen_aliases import abi
        from placelink import CRT_NAME
        for address,cleanup in runtime.items():
            known=[n for n, in self.db.execute('SELECT DISTINCT name FROM binding WHERE address=?',(address,)) if CRT_NAME.match(n)]
            declarations=[(n,abi(n)) for n in known]
            signatures={(a['convention'],a['cleanup']) for n,a in declarations if a['convention'] is not None and a['cleanup'] is not None}
            implementation=next(((n,a) for n,a in declarations if (a['convention'],a['cleanup']) in signatures),None) if len(signatures)==1 else None
            issue(self.db,'runtime_abi',address=hx(address),cleanup=cleanup,
                  implementation=implementation[0] if implementation else None,
                  implementation_abi=implementation[1] if implementation else None)
        self.define_labels(c,parts)
        c.write(self.out/'image_code.obj')
        dump(self.out/'external_short_branches.json',shorts)
        dump(self.out/'code_branch_audit.json',branch_trace)
        self.code_parts=parts

    def code_fixed_point(self):
        # A later fragment can reveal a callable entry in an earlier fragment.
        # Rescan until all such entries have been traversed before emitting the
        # final object; one address-order pass can leave stale relative operands.
        initial_counts=self.counts.copy()
        passes=0
        while True:
            before=self.db.execute('SELECT COUNT(*) FROM address').fetchone()[0]
            self.counts=initial_counts.copy()
            self.db.execute("DELETE FROM issue WHERE kind IN ('runtime_abi','external_short_branch')")
            self.code()
            passes+=1
            after=self.db.execute('SELECT COUNT(*) FROM address').fetchone()[0]
            if before==after:
                self.counts['code_discovery_passes']=passes
                return

    def return_cleanup(self,entry,lo,hi,decoded):
        todo=[entry];visited=set();returns=set();uncertain=False
        while todo and len(visited)<4096:
            a=todo.pop()
            while lo<=a<hi and a not in visited:
                i=decoded.get(a)
                if i is None or not i.id:uncertain=True;break
                visited.add(a)
                if i.group(3):
                    returns.add(i.operands[0].imm if i.operands else 0);break
                if i.group(1):
                    dest=next((op.imm & 0xffffffff for op in i.operands if op.type==X86_OP_IMM),None)
                    if dest is not None and lo<=dest<hi:todo.append(dest)
                    else:uncertain=True
                    if i.mnemonic=='jmp':break
                if i.mnemonic in ('int3','ud2','hlt'):break
                a+=i.size
                if a==hi:uncertain=True
        return next(iter(returns)) if len(returns)==1 and not uncertain and not todo else None

    def resources(self):
        start,size=self.pe.directory(2)
        if not start:return
        s=self.pe.section(start)
        c=COFF();sn=c.section('.rsrc$01',self.pe.read(start,size),0x40300040)
        c.symbol('_fnv_resource_root',sn,0)
        seen=set();todo=[0];leaves=set()
        while todo:
            off=todo.pop()
            if off in seen:continue
            seen.add(off)
            if off+16>size:raise ValueError('resource directory outside .rsrc')
            named,ids=struct.unpack('<HH',self.pe.read(start+off+12,4))
            for i in range(named+ids):
                _,item=struct.unpack('<II',self.pe.read(start+off+16+i*8,8))
                if item & 0x80000000:todo.append(item & 0x7fffffff)
                else:leaves.add(item)
        for off in leaves:
            rva,n,cp,reserved=struct.unpack('<IIII',self.pe.read(start+off,16))
            target=self.pe.base+rva
            if not start<=target<=start+size-n:raise ValueError('external resource payload')
            c.reloc(sn,off,'_fnv_resource_root',7,target-start)
        c.write(self.out/'image_resources.obj')
        self.counts['resource_leaves']=len(leaves);self.counts['resource_bytes']=size

    def validate_mapping(self):
        owned=self.owner
        ranges=sorted([(a,b) for a,b,k,sn in self.parts+self.code_parts])
        rr=merged(ranges);starts=[a for a,b in rr]
        def generated(a):
            i=bisect_right(starts,a)-1
            return i>=0 and rr[i][0]<=a<rr[i][1]
        unmapped=[]
        for a,reason in self.db.execute('SELECT address,reason FROM address ORDER BY address'):
            if reason=='absolute_constant' or self.pe.base<=a<self.pe.base+self.pe.header_size:continue
            if owned(a) or generated(a) or self.db.execute('SELECT 1 FROM import WHERE address=?',(a,)).fetchone():continue
            unmapped.append(dict(address=hx(a),reason=reason))
            issue(self.db,'unmapped_address',address=hx(a),reason=reason)
        for site,target in self.highlow.items():
            if not (owned(site) or generated(site)):
                issue(self.db,'unmapped_HIGHLOW_site',address=hx(site),target=hx(target))
            else:self.counts['HIGHLOW_sites_mapped']+=1
            if owned(target) or generated(target) or self.pe.base<=target<self.pe.base+self.pe.header_size or self.db.execute('SELECT 1 FROM import WHERE address=?',(target,)).fetchone():
                self.counts['HIGHLOW_targets_mapped']+=1
            else:
                issue(self.db,'unmapped_HIGHLOW_target',address=hx(site),target=hx(target))
        self.counts['original_HIGHLOW_count']=len(self.highlow)
        self.counts['unmapped_addresses']=len(unmapped)
        dump(self.out/'unmapped_addresses.json',unmapped)

    def run(self):
        self.discover()
        # Code discovery can introduce data or compiler-interior labels, so it
        # must precede finalizing the data and augmented compiler objects.
        self.code_fixed_point();self.data();self.resources();self.validate_mapping()
        self.db.commit()
        result=dict(counts=dict(self.counts),entry=hx(self.pe.entry),entry_symbol=label(self.pe.entry),dos_stub_bytes=0,
                    tls_callbacks=[hx(a) for a in self.tls_callbacks],
                    runtime='Original static runtime; /NODEFAULTLIB; no libcmt/libcpmt fallback',
                    image_sha256=__import__('hashlib').sha256(self.pe.data).hexdigest())
        dump(self.out/'image_report.json',result)
        return result
