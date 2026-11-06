"""Native link ownership policies; modifies build copies only."""
from collections import Counter, defaultdict, deque
import json
import struct
import sys

from standalone_common import TREE, dump, hx, label


def ownership(db, units, objects, pe, out):
    sys.path.insert(0,str(TREE/'tools'))
    from compare import Coff, LITERAL, same_literal
    db.execute('CREATE TABLE IF NOT EXISTS matched_reference(name TEXT,unit INTEGER,PRIMARY KEY(name,unit))')
    db.execute('DELETE FROM matched_reference')
    globalmap={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding GROUP BY name HAVING COUNT(DISTINCT address)=1')}
    boundnames={n for n, in db.execute('SELECT DISTINCT name FROM binding')}
    plans={}; counts=Counter(); records=[]
    for oi,(u,path) in enumerate(zip(units,objects)):
        c=Coff(path)
        local={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding WHERE unit=? GROUP BY name HAVING COUNT(DISTINCT address)=1',(oi,))}
        matched=defaultdict(list)
        for lo,hi,sn,off in db.execute('SELECT lo,hi,section,offset FROM span WHERE unit=?',(oi,)):
            matched[sn].append((off,off+hi-lo))
        evidence=defaultdict(set)
        for sn,ll in matched.items():
            for off,ti,kind in c.sections[sn]['relocs']:
                if any(lo<=off and off+4<=hi for lo,hi in ll):
                    db.execute('INSERT OR IGNORE INTO matched_reference VALUES (?,?)',(c.symbols[ti]['name'],oi))
        for lo,hi,sn,start in db.execute('SELECT lo,hi,section,offset FROM span WHERE unit=?',(oi,)):
            for off,ti,kind in c.sections[sn]['relocs']:
                t=c.symbols[ti]
                if t['section']<=0 or c.sections[t['section']]['flags']&0x20 or kind not in (6,7,20) or not start<=off or off+4>start+hi-lo:continue
                observed=struct.unpack('<i' if kind==20 else '<I',pe.read(lo+off-start,4))[0]
                if kind==20:observed+=lo+off-start+4
                if kind==7:observed+=pe.base
                addend=struct.unpack_from('<i' if kind==20 else '<I',c.sections[sn]['data'],off)[0]
                evidence[ti].add((observed-addend)&0xffffffff)
        targets={}; startup=[]; removed=[];unresolved={}
        for sn,sec in enumerate(c.sections[1:],1):
            if sec['name'].startswith(('.CRT$XC','.CRT$XI','.CRT$XT')):
                startup.append(sn);counts['startup_sections_dropped']+=1
                counts['startup_bytes_dropped']+=len(sec['data'])
                db.execute('DELETE FROM definition WHERE unit=? AND section=?',(oi,sn))
                continue
            if sec['flags']&0x20 or sec['name'].startswith('.tls'):continue
            defined=[(ix,t) for ix,t in c.symbols.items() if t['section']==sn and (t['storage']==2 or ix in evidence)]
            for ix,t in defined:
                a=local.get(t['name'])
                if a is None and t['storage']==2:a=globalmap.get(t['name'])
                if a is None and len(evidence[ix])==1:
                    a=next(iter(evidence[ix]));counts['observed_data_symbols_canonicalized']+=1
                elif a is not None and evidence[ix] and a not in evidence[ix]:
                    if LITERAL.match(t['name']) and all(same_literal(c,pe,t,a,b) for b in evidence[ix]):
                        counts['equivalent_constant_pool_addresses']+=1
                    else:
                        from standalone_common import issue
                        issue(db,'data_binding_mismatch',unit=oi,symbol=t['name'],recipe=hx(a),observed=[hx(v) for v in sorted(evidence[ix])])
                if a is None and t['storage']==2 and t['name'] in boundnames:
                    bb=[b for b, in db.execute('SELECT DISTINCT address FROM binding WHERE name=?',(t['name'],))]
                    literals=[b for b in bb if pe.section(b) and same_literal(c,pe,t,b,b)] if LITERAL.match(t['name']) else []
                    if literals:
                        a=min(literals);counts['pooled_literal_compiler_definitions_dropped']+=1
                    elif any(pe.section(b) and pe.section(b)['name'] in ('.data','.rdata','CONST') for b in bb):
                        # The name is a source collision even in this unit,
                        # which supplies no address evidence. Drop its compiler
                        # definition and leave an explicit conflicting external.
                        unresolved[ix]=dict(name=t['name'],delta=0)
                        db.execute('DELETE FROM definition WHERE unit=? AND name=? AND section=?',(oi,t['name'],sn))
                        db.execute('INSERT OR IGNORE INTO reference VALUES (?,?)',(t['name'],oi))
                        counts['conflicting_data_definitions_dropped']+=1
                        continue
                s=pe.section(a) if a is not None else None
                if not s or s['name'] not in ('.data','.rdata','CONST'):continue
                targets[ix]=a
                db.execute('DELETE FROM definition WHERE unit=? AND name=? AND section=?',(oi,t['name'],sn))
                db.execute('INSERT OR IGNORE INTO address VALUES (?,?)',(a,'data_canonical'))
                # All references to this compiler definition are rewritten to
                # the generated address label; no global weak alias is needed.
                counts['mutable_definitions_dropped' if sec['flags']&0x80000000 else 'constant_definitions_canonicalized']+=1
                records.append(dict(unit=oi,source=u['source'],object=str(path),section=sn,symbol=t['name'],address=hx(a)))
            if defined and all(ix in targets for ix,t in defined):
                # Section-relative/static aliases are safe only if all anchors
                # agree on the original layout. Otherwise retain inaccessible
                # compiler bytes while redirecting each named global separately.
                bases={targets[ix]-t['value'] for ix,t in defined}
                if len(bases)==1:
                    base=next(iter(bases))
                    if pe.section(base) and pe.section(base+max(0,len(sec['data'])-1))==pe.section(base):
                        for ix,t in c.symbols.items():
                            if t['section']==sn:targets[ix]=base+t['value']
                        removed.append(sn);counts['bound_data_sections_dropped']+=1
            elif len(defined)==1 and defined[0][0] in unresolved:
                ix,anchor=defined[0];removed.append(sn)
                for ti,t in c.symbols.items():
                    if t['section']==sn:unresolved[ti]=dict(name=anchor['name'],delta=t['value']-anchor['value'])
            counts['compiler_constant_definitions_retained']+=sum(ix not in targets and ix not in unresolved for ix,t in defined) if not sec['flags']&0x80000000 else 0
        for a in targets.values():
            db.execute('INSERT OR IGNORE INTO address VALUES (?,?)',(a,'data_canonical'))
        plans[oi]=dict(symbols=targets,sections=removed,startup=startup,unresolved=unresolved)
        if oi%100==0:db.commit()
    # The storage ownership policy supersedes the byte-identity gate.
    db.execute("DELETE FROM issue WHERE kind='unproved_mutable_data_identity'")
    db.commit()
    dump(out/'ownership_report.json',dict(counts=counts,policy='Generated storage owns every recipe-bound data symbol; unbound compiler constants retain compiler ownership.'))
    dump(out/'global_ownership.json',records)
    dump(out/'policy_rewrite_plan.json',plans)
    return plans


class CoffView:
    """Read-only COFF view including generated relocation-overflow sections."""
    def __init__(self,path):
        self.data=path.read_bytes();d=self.data
        _,count,_,ptr,n,_,_=struct.unpack_from('<HHIIIHH',d)
        self.ptr,self.n=ptr,n
        strings=d[ptr+n*18:]
        def string(offset):
            end=strings.find(b'\0',offset)
            return strings[offset:end if end>=0 else len(strings)].decode()
        def name(raw):
            if raw[:4]==bytes(4):return string(struct.unpack_from('<I',raw,4)[0])
            if raw.startswith(b'/'):
                return string(int(raw[1:].rstrip(b'\0')))
            return raw.rstrip(b'\0').decode()
        self.symbols={};i=0
        while i<n:
            raw,v,s,t,storage,aux=struct.unpack_from('<8sIhHBB',d,ptr+i*18)
            self.symbols[i]=dict(name=name(raw),value=v,section=s,storage=storage,aux=aux)
            i+=1+aux
        self.sections=[None]
        for sn in range(1,count+1):
            raw,_,_,size,rp,rr,_,nr,_,flags=struct.unpack_from('<8sIIIIIIHHI',d,20+(sn-1)*40)
            skip=0
            if flags&0x1000000:nr=struct.unpack_from('<I',d,rr)[0]-1;skip=10
            rels=[struct.unpack_from('<IIH',d,rr+skip+j*10) for j in range(nr)]
            self.sections.append(dict(name=name(raw),flags=flags,size=size,raw=rp,relocs=rels))


def canonical_code_references(db,objects,pe,out):
    """Bound names mean their proved address even when a compiler copy defines them.

    A weak external cannot override a strong COMDAT definition. Rewrite its
    relocating references to the implementing address label in the build copy;
    otherwise decorated-name lookup spuriously roots unmatched inline copies.
    Matched relocation operands identify their own exact target even where a
    stand-in name collides across units. Unmatched conflicting names remain
    explicit source reconciliation; no competing implementation is selected.
    """
    from standalone_common import append_symbols
    proved={n for n, in db.execute('SELECT DISTINCT name FROM matched_reference')}
    mapping={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding GROUP BY name HAVING COUNT(DISTINCT address)=1')
             if n in proved and pe.section(a) and pe.section(a)['name'] in ('.text','.rdata','.data','.tls','CONST')}
    imports=dict(db.execute('SELECT address,symbol FROM import'))
    highlow=dict(pe.relocations())
    counts=Counter();records=[]
    for oi,path in enumerate(objects):
        c=CoffView(path);d=bytearray(c.data);names={t['name']:ix for ix,t in c.symbols.items() if t['storage']==2};added=[];changed=0;exact=0
        matched=defaultdict(list)
        for lo,hi,sn,start in db.execute('SELECT lo,hi,section,offset FROM span WHERE unit=?',(oi,)):
            matched[sn].append((lo,hi,start))
        for sn,sec in enumerate(c.sections[1:],1):
            if sec['flags']&0x800 or sec['name'].startswith('.debug'):continue
            rp=struct.unpack_from('<I',d,20+(sn-1)*40+24)[0]
            removed=set()
            for j,(off,ti,kind) in enumerate(sec['relocs']):
                t=c.symbols[ti]
                if kind not in (6,7,11,20):continue
                a=mapping.get(t['name']) if t['storage'] in (2,105) else None
                owners=[(lo,hi,start) for lo,hi,start in matched[sn] if start<=off and off+4<=start+hi-lo]
                if owners:
                    if kind==6:
                        sites=[lo+off-start for lo,hi,start in owners]
                        relocatable={site in highlow for site in sites}
                        if len(relocatable)!=1:raise ValueError('overlapping matched relocation kinds disagree')
                        if not relocatable.pop():
                            # Address-shaped stand-ins can encode integer masks.
                            # The original PE relocation table, not the spelling
                            # or numerical range of a target, determines DIR32.
                            values={pe.read(site,4) for site in sites}
                            if len(values)!=1:raise ValueError('overlapping matched literal proofs disagree')
                            d[sec['raw']+off:sec['raw']+off+4]=values.pop()
                            removed.add(j);changed+=1
                            counts['literal_relocations_removed']+=1
                            continue
                    observed=set()
                    for lo,hi,start in owners:
                        original=struct.unpack('<i' if kind==20 else '<I',pe.read(lo+off-start,4))[0]
                        if kind==20:original+=lo+off-start+4
                        if kind==7:original+=pe.base
                        if kind==11:original+=next(s['lo'] for s in pe.sections if s['name']=='.tls')
                        addend=struct.unpack_from('<i' if kind==20 else '<I',d,sec['raw']+off)[0]
                        observed.add((original-addend)&0xffffffff)
                    if len(observed)!=1:raise ValueError('overlapping matched relocation proofs disagree')
                    a=observed.pop();exact+=1
                    if kind==11:
                        # SECREL must name the actual TLS field, not the base
                        # of a stand-in struct/array which can precede .tls.
                        a=(a+addend)&0xffffffff
                        struct.pack_into('<I',d,sec['raw']+off,0)
                if a is None:continue
                if not pe.section(a):continue
                target=imports.get(a,label(a))
                if t['name']==target:continue
                if target not in names:names[target]=c.n+len(added);added.append((target,0,0))
                struct.pack_into('<I',d,rp+j*10+4,names[target]);changed+=1
            if removed:
                kept=[bytes(d[rp+j*10:rp+(j+1)*10]) for j in range(len(sec['relocs'])) if j not in removed]
                payload=b''.join(kept)
                d[rp:rp+len(payload)]=payload
                struct.pack_into('<H',d,20+(sn-1)*40+32,len(kept))
                for symbol_index,symbol in c.symbols.items():
                    if symbol['section']==sn and symbol['storage']==3 and symbol['aux'] and symbol['name']==sec['name']:
                        struct.pack_into('<H',d,c.ptr+(symbol_index+1)*18+4,len(kept))
        if changed:
            path.write_bytes(d)
            if added:append_symbols(path,path,added)
            records.append(dict(unit=oi,object=path.name,rewritten_references=changed,exact_matched_operands=exact))
            counts['rewritten_references']+=changed;counts['objects_changed']+=1;counts['exact_matched_operands']+=exact
    dump(out/'code_address_rewrites.json',dict(counts=counts,objects=records,policy='Original HIGHLOW sites distinguish DIR32 pointers from literal operands. Exact matched relocations resolve by their own proved target; globally unambiguous proved names also resolve unmatched copies. No ambiguous unmatched reference is guessed.'))
    return counts


def discard_unreachable(db,objects,pe,out,accumulate=False):
    """Materialize /OPT:REF before VC9's eager duplicate/undefined checks.

    Original generated data/code remain retained sections, rooting init tables
    and every original pointer. Compiler sections without any incoming reference
    have no original storage identity and may be discarded as build-copy debris.
    All alternatives for a duplicated external are visited, so this cannot hide
    a reachable naming collision by arbitrarily selecting an implementation.
    """
    generated=[out/n for n in ('image_code.obj','image_data.obj','image_resources.obj') if (out/n).exists()]
    paths=objects+generated
    nodes={};edges=defaultdict(set);definitions=defaultdict(set);roots=set();weak={};association=defaultdict(set);directive_aliases=defaultdict(set)
    import re
    for oi,path in enumerate(paths):
        c=CoffView(path)
        for s in c.sections[1:]:
            if s['name']=='.drectve':
                raw=c.data[s['raw']:s['raw']+s['size']]
                for m in re.finditer(rb'/alternatename:(?:"([^"]+)"|(\S+))',raw,re.I):
                    name,target=(m[1] or m[2]).decode().split('=',1)
                    directive_aliases[name].add(target)
        for sn,s in enumerate(c.sections[1:],1):
            if s['flags']&0xa00 or s['name'].startswith('.debug') or s['name']=='.sxdata':continue
            node=(oi,sn);nodes[node]=s['flags']
            if oi>=len(objects):roots.add(node)
        for ix,t in c.symbols.items():
            sn=t['section']
            if sn>0 and (oi,sn) in nodes and t['storage']==2:definitions[t['name']].add((oi,sn))
            if t['storage']==105:
                fallback,search=struct.unpack_from('<II',c.data,c.ptr+(ix+1)*18)
                weak[oi,t['name']]=c.symbols[fallback]['name']
            if sn>0 and t['storage']==3 and t['aux']:
                aux=c.ptr+(ix+1)*18
                if c.data[aux+14]==5 and not c.sections[sn]['name'].startswith(('.text$x','.xdata')):
                    # Matched parent pointers now name the original EH storage.
                    # A compiler EH copy needs an actual incoming relocation;
                    # association alone cannot root its unmatched cleanup calls.
                    parent=struct.unpack_from('<h',c.data,aux+12)[0]
                    if (oi,sn) in nodes and (oi,parent) in nodes:
                        association[oi,parent].add((oi,sn));association[oi,sn].add((oi,parent))
        for sn,s in enumerate(c.sections[1:],1):
            node=(oi,sn)
            if node not in nodes:continue
            for off,ti,kind in s['relocs']:
                t=c.symbols[ti]
                if t['storage'] in (2,105):edges[node].add(t['name'])
                elif t['section']>0 and (oi,t['section']) in nodes:edges[node].add((oi,t['section']))
    aliases={n:t for n,t in db.execute("SELECT name,target FROM alias WHERE status LIKE 'ok%' AND name!=target")}
    used_aliases=set();used_names=set();live=set();pending=deque(roots)
    def resolve(name,oi,seen=None):
        seen=set() if seen is None else seen
        if name in seen:return set()
        seen.add(name);used_names.add(name)
        if name in definitions:return definitions[name]
        if name in aliases:
            used_aliases.add(name);return resolve(aliases[name],oi,seen)
        if (oi,name) in weak:return resolve(weak[oi,name],oi,seen)
        if name in directive_aliases:
            found=set()
            for target in directive_aliases[name]:found.update(resolve(target,oi,set(seen)))
            return found
        return set()
    pending.extend(resolve(label(pe.entry),-1))
    pending.extend(resolve('__tls_used',-1))
    for a in json.loads((out/'image_report.json').read_text())['tls_callbacks']:
        pending.extend(resolve(label(int(a,16)),-1))
    while pending:
        node=pending.popleft()
        if node in live:continue
        live.add(node);pending.extend(association.get(node,()))
        for target in edges.get(node,()):
            if isinstance(target,str):pending.extend(resolve(target,node[0]))
            else:pending.append(target)
    dropped=[];counts=Counter()
    for oi,path in enumerate(objects):
        c=CoffView(path);d=bytearray(c.data);dead={sn for sn,s in enumerate(c.sections[1:],1)
            if (oi,sn) in nodes and (oi,sn) not in live}
        # Address-rooted matched EH tails can outlive their compiler parent:
        # canonical calls may use another implementation of that parent. Native
        # LINK discards an associative child with the parent even when a public
        # address label in the child is referenced. Give proved live EH storage
        # independent ownership; unreferenced compiler EH copies remain dead.
        proved_eh={sn for sn, in db.execute("SELECT DISTINCT section FROM span WHERE unit=? AND kind='eh'",(oi,))}
        for ix,t in c.symbols.items():
            sn=t['section']
            if sn in proved_eh and (oi,sn) in live and t['storage']==3 and t['aux']:
                aux=c.ptr+(ix+1)*18
                if c.data[aux+14]==5:
                    flags=struct.unpack_from('<I',d,20+(sn-1)*40+36)[0]
                    struct.pack_into('<I',d,20+(sn-1)*40+36,flags&~0x1000)
                    d[aux+14]=0;struct.pack_into('<h',d,aux+12,0)
                    counts['live_matched_eh_associations_detached']+=1
        # /SAFESEH:NO already disables the compiler's redundant handler index.
        dead|={sn for sn,s in enumerate(c.sections[1:],1) if s['name']=='.sxdata' or s['name'].startswith('.debug')}
        # Source scaffolds use dllexport to retain matching-only locals. The
        # original executable has no exports; those are not runtime roots.
        for s in c.sections[1:]:
            if s['name']=='.drectve' and not pe.directory(0)[0]:
                start=s['raw'];raw=bytes(d[start:start+s['size']])
                for m in re.finditer(rb'/EXPORT:(?:"[^"]*"|\S+)',raw,re.I):
                    d[start+m.start():start+m.end()]=b' '*(m.end()-m.start())
                    counts['compiler_export_directives_dropped']+=1
            if s['name']=='.drectve':
                start=s['raw'];raw=bytes(d[start:start+s['size']])
                for m in re.finditer(rb'/INCLUDE:(?:"[^"]*"|\S+)',raw,re.I):
                    d[start+m.start():start+m.end()]=b' '*(m.end()-m.start())
                    counts['compiler_matching_include_directives_dropped']+=1
        referenced=set()
        for sn,s in enumerate(c.sections[1:],1):
            if sn not in dead and not s['flags']&0x800:
                referenced.update(ti for off,ti,kind in s['relocs'])
        for sn in dead:
            s=c.sections[sn];struct.pack_into('<I',d,20+(sn-1)*40+36,(s['flags']|0x800)&~0x1000)
            names=[t['name'] for t in c.symbols.values() if t['section']==sn and t['storage']==2]
            dropped.append(dict(unit=oi,object=path.name,section=sn,symbols=names,size=s['size']))
            counts['discarded_sections']+=1;counts['discarded_bytes']+=s['size']
        for ix,t in c.symbols.items():
            sn=t['section'];pos=c.ptr+ix*18
            if sn in dead and t['storage']==3 and t['aux']:
                d[pos+18+14]=0;struct.pack_into('<h',d,pos+18+12,0)
            if sn in dead or (sn==0 and t['storage'] in (2,105) and ix not in referenced):
                # VC9 resolves symbol-table undefineds even when their only
                # relocating contribution is dead. Neutralize those records.
                struct.pack_into('<Ih',d,pos+8,0,-1);d[pos+16]=3
                if t['storage']==105:d[pos+18:pos+36]=bytes(18)
        path.write_bytes(d)
    from gen_aliases import weak_aliases
    pairs=[(n,aliases[n]) for n in sorted(used_aliases)]
    weak_aliases(pairs,out/'aliases.obj')
    from standalone_common import COFF
    c=COFF();c.section('.drectve',(' '+' '.join('/alternatename:'+n+'='+t for n,t in pairs)+' ').encode(),0x100a00)
    c.write(out/'aliases_directives.obj')
    db.execute('CREATE TABLE IF NOT EXISTS live_name(name TEXT PRIMARY KEY)')
    db.execute('DELETE FROM live_name');db.executemany('INSERT INTO live_name VALUES (?)',[(n,) for n in used_names]);db.commit()
    if accumulate:
        old=json.loads((out/'reachability_report.json').read_text())['counts']
        records={(r['unit'],r['section']):r for r in json.loads((out/'discarded_comdats.json').read_text())}
        records.update({(r['unit'],r['section']):r for r in dropped});dropped=list(records.values())
        counts['discarded_sections']=len(dropped);counts['discarded_bytes']=sum(r['size'] for r in dropped)
        counts['compiler_export_directives_dropped']+=old.get('compiler_export_directives_dropped',0)
        counts['compiler_matching_include_directives_dropped']+=old.get('compiler_matching_include_directives_dropped',0)
    counts.update(total_sections=old['total_sections'] if accumulate else len(nodes),live_sections=len(live),aliases_retained=len(pairs),aliases_discarded=len(aliases)-len(pairs))
    dump(out/'reachability_report.json',dict(counts=counts,roots='Entry, TLS directory/callbacks, original generated data/code including original initialization tables',conservative_duplicate_edges='All competing definitions retained when a decorated name is reachable'))
    dump(out/'discarded_comdats.json',dropped)
    return counts


def trim_unmatched_eh(db,objects,out):
    """Remove unreachable holes within mixed matched/unmatched EH contributions.

    Keep offsets and all matched bytes unchanged. Before erasing a hole, prove
    no retained relocation or non-relocated branch/fallthrough enters it. Original
    generated code implements its original addresses independently.
    """
    from capstone import Cs,CS_ARCH_X86,CS_MODE_32
    from capstone.x86 import X86_OP_IMM
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    records=[];counts=Counter()
    for oi,path in enumerate(objects):
        regions=defaultdict(list)
        for sn,start,size in db.execute("SELECT section,offset,hi-lo FROM span WHERE unit=? AND kind='eh'",(oi,)):
            regions[sn].append((start,start+size))
        if not regions:continue
        c=CoffView(path);candidate={}
        for sn,rr in regions.items():
            sec=c.sections[sn]
            if sec['flags']&0x800 or not sec['name'].startswith('.text$x'):continue
            rr=sorted(set(rr));merged=[]
            for a,b in rr:
                if merged and a<=merged[-1][1]:merged[-1][1]=max(b,merged[-1][1])
                else:merged.append([a,b])
            if merged==[[0,sec['size']]]:continue
            if not all(0<=a<b<=sec['size'] for a,b in merged):raise ValueError('EH coverage outside contribution')
            candidate[sn]=merged
        if not candidate:continue
        def inside(sn,a,b=None):
            b=a+1 if b is None else b
            return any(lo<=a and b<=hi for lo,hi in candidate[sn])
        for sn,rr in candidate.items():
            sec=c.sections[sn];relocs={off for off,ti,k in sec['relocs']}
            for lo,hi in rr:
                instructions=list(md.disasm(c.data[sec['raw']+lo:sec['raw']+hi],lo))
                if not instructions or instructions[-1].address+instructions[-1].size!=hi:
                    raise ValueError('EH island is not a complete instruction range')
                for ins in instructions:
                    if not (ins.group(1) or ins.group(2)) or ins.address+ins.imm_offset in relocs:continue
                    dest=next((op.imm for op in ins.operands if op.type==X86_OP_IMM),None)
                    if dest is not None and not inside(sn,dest):
                        raise ValueError('retained EH branch enters an unproved hole')
                last=instructions[-1]
                if hi<sec['size'] and not inside(sn,hi) and not (last.group(3) or last.mnemonic in ('jmp','int3','ud2','hlt')):
                    raise ValueError('retained EH code falls through into an unproved hole')
        for sn,sec in enumerate(c.sections[1:],1):
            if sec['flags']&0x800 or sec['name'].startswith('.debug'):continue
            for off,ti,kind in sec['relocs']:
                if sn in candidate and not inside(sn,off,off+4):continue
                target=c.symbols[ti];ts=target['section']
                if ts not in candidate:continue
                if kind not in (6,20):raise ValueError('unsupported EH interior relocation')
                addend=struct.unpack_from('<i' if kind==20 else '<I',c.data,sec['raw']+off)[0]
                if not inside(ts,target['value']+addend):
                    raise ValueError('live relocation enters an unmatched EH hole: %d/%d'%(oi,ts))
        data=bytearray(c.data)
        for sn,rr in candidate.items():
            sec=c.sections[sn];kept=[r for r in sec['relocs'] if inside(sn,r[0],r[0]+4)]
            rp=struct.unpack_from('<I',data,20+(sn-1)*40+24)[0]
            if sec['flags']&0x1000000:raise ValueError('unexpected EH relocation overflow')
            for j,reloc in enumerate(kept):struct.pack_into('<IIH',data,rp+j*10,*reloc)
            struct.pack_into('<H',data,20+(sn-1)*40+32,len(kept))
            holes=[];pos=0
            for lo,hi in rr:
                if pos<lo:holes.append((pos,lo))
                pos=hi
            if pos<sec['size']:holes.append((pos,sec['size']))
            for lo,hi in holes:data[sec['raw']+lo:sec['raw']+hi]=b'\xcc'*(hi-lo)
            for ix,t in c.symbols.items():
                if t['section']!=sn:continue
                if t['storage']==3 and t['aux']:
                    struct.pack_into('<H',data,c.ptr+(ix+1)*18+4,len(kept))
                    continue
                if not inside(sn,t['value']):
                    if t['storage']==2 and db.execute('SELECT 1 FROM live_name WHERE name=?',(t['name'],)).fetchone():
                        raise ValueError('live external enters unmatched EH hole')
                    struct.pack_into('<Ih',data,c.ptr+ix*18+8,0,-1);data[c.ptr+ix*18+16]=3
            records.append(dict(unit=oi,object=path.name,section=sn,retained_ranges=rr,discarded_ranges=holes,
                                relocations_removed=len(sec['relocs'])-len(kept)))
            counts['sections_trimmed']+=1;counts['bytes_discarded']+=sum(b-a for a,b in holes)
            counts['relocations_removed']+=len(sec['relocs'])-len(kept)
        path.write_bytes(data);counts['objects_changed']+=1
    dump(out/'eh_trim_report.json',dict(counts=counts,sections=records))
    return counts


def reconcile_comdats(db,objects,out):
    """Permit ANY only after comparing bytes AND relocation identities."""
    import hashlib
    from standalone_common import append_symbols
    events=json.loads((out/'native_duplicates.json').read_text())
    wanted={r['symbol'] for r in events}
    groups=defaultdict(list);views={}
    aliases={n:t for n,t in db.execute("SELECT name,target FROM alias WHERE status LIKE 'ok%'")}
    globalmap={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding GROUP BY name HAVING COUNT(DISTINCT address)=1')}
    needed_objects={r[k] for r in events for k in ('object','previous_object')}
    for oi,path in enumerate(objects):
        if path.name not in needed_objects:continue
        c=CoffView(path);views[oi]=(path,c)
        local={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding WHERE unit=? GROUP BY name HAVING COUNT(DISTINCT address)=1',(oi,))}
        ss=list(db.execute('SELECT lo,hi,section,offset FROM span WHERE unit=?',(oi,)))
        def address(t):
            name=t['name']
            if name.startswith('_fnv_va_'):return int(name[8:],16)
            a=local.get(name,globalmap.get(name))
            if a is not None:return a
            for lo,hi,sn,offset in ss:
                if sn==t['section'] and offset<=t['value']<offset+hi-lo:return lo+t['value']-offset
            return None
        def private_body(sn,stack):
            if sn in stack:return 'cycle:%d'%(len(stack)-stack.index(sn))
            if len(stack)>64:return 'unproved:%d:%d'%(oi,sn)
            sec=c.sections[sn]
            raw=bytearray(c.data[sec['raw']:sec['raw']+sec['size']]) if sec['raw'] else bytearray(sec['size'])
            rr=[]
            for off,ti,kind in sec['relocs']:
                t=c.symbols[ti];addend=struct.unpack_from('<i' if kind==20 else '<I',raw,off)[0];raw[off:off+4]=bytes(4)
                a=address(t)
                if a is not None:identity=('address',hx((a+addend)&0xffffffff))
                elif t['section']==sn:identity=('self',t['value']+addend)
                elif t['section']>0 and t['storage'] not in (2,105):
                    identity=('private_body',private_body(t['section'],stack+(sn,)),t['value']+addend)
                else:identity=('symbol',aliases.get(t['name'],t['name']),addend)
                rr.append((off,kind,identity))
            return hashlib.sha256(raw+json.dumps((sec['flags']&0xe00000e0,rr),separators=(',',':')).encode()).hexdigest()
        for ix,t in c.symbols.items():
            sn=t['section']
            if t['name'] not in wanted or sn<=0 or c.sections[sn]['flags']&0x800:continue
            sec=c.sections[sn];raw=bytearray(c.data[sec['raw']:sec['raw']+sec['size']]) if sec['raw'] else bytearray(sec['size'])
            rels=[]
            for off,ti,kind in sec['relocs']:
                target=c.symbols[ti];addend=struct.unpack_from('<i' if kind==20 else '<I',raw,off)[0]
                raw[off:off+4]=bytes(4)
                a=address(target)
                if a is not None:identity=('address',hx((a+addend)&0xffffffff))
                elif target['section']==sn:identity=('self',target['value']+addend)
                elif target['storage'] not in (2,105) and target['section']>0:
                    # Compare private EH/data recursively; equal section names
                    # alone do not prove equal relocation destinations.
                    identity=('private_body',private_body(target['section'],(sn,)),target['value']+addend)
                else:identity=('symbol',aliases.get(target['name'],target['name']),addend)
                rels.append((off,kind,identity))
            normalized=json.dumps(rels,separators=(',',':')).encode()
            sha=hashlib.sha256(raw+normalized).hexdigest()
            locations=[hx(lo+t['value']-offset) for lo,hi,sno,offset in ss if sno==sn and offset<=t['value']<offset+hi-lo]
            if not locations:
                a=local.get(t['name'],globalmap.get(t['name']))
                locations=[hx(a)] if a is not None else []
            groups[t['name']].append(dict(unit=oi,object=path.name,section=sn,offset=t['value'],addresses=locations,
                byte_hash=hashlib.sha256(raw).hexdigest(),relocation_hash=hashlib.sha256(normalized).hexdigest(),body_hash=sha,size=sec['size']))
    report=[];changes=defaultdict(set);additions=defaultdict(list);remove=defaultdict(set);redirects=defaultdict(dict)
    for name,entries in sorted(groups.items()):
        identical=len(entries)>1 and len({e['body_hash'] for e in entries})==1 and len({e['offset'] for e in entries})==1
        report.append(dict(symbol=name,identical=identical,action='selection_ANY' if identical else 'source_naming_collision',definitions=entries))
        if not identical:continue
        labels=set();representative=min(entries,key=lambda e:(e['unit'],e['section']))
        repunit,repsn=representative['unit'],representative['section']
        for e in entries:
            path,c=views[e['unit']];sn=e['section']
            labels.update((t['name'],t['value']) for t in c.symbols.values() if t['section']==sn and t['name'].startswith('_fnv_va_'))
            if e is representative:continue
            remove[e['unit']].add(sn)
            for ix,t in c.symbols.items():
                if t['section']==sn and t['storage'] not in (2,105):
                    alias='_fnv_comdat_%d_%d_%d'%(e['unit'],sn,t['value'])
                    redirects[e['unit']][ix]=alias;labels.add((alias,t['value']))
        path,c=views[repunit];existing={t['name'] for t in c.symbols.values()}
        additions[repunit].extend((n,repsn,v) for n,v in labels if n not in existing)
        changes[repunit].add(repsn)
    for oi in set(changes)|set(remove):
        sections=changes[oi]
        path,c=views[oi];d=bytearray(c.data)
        for ix,t in c.symbols.items():
            if t['section'] in sections and t['storage']==3 and t['aux'] and d[c.ptr+(ix+1)*18+14] in (1,2,3,4):
                d[c.ptr+(ix+1)*18+14]=2
            if t['section'] in remove[oi]:
                if t['storage']==2:struct.pack_into('<Ih',d,c.ptr+ix*18+8,0,0)
                if t['storage']==3 and t['aux']:
                    d[c.ptr+(ix+1)*18+14]=0;struct.pack_into('<h',d,c.ptr+(ix+1)*18+12,0)
        extnames=sorted(set(redirects[oi].values()));extindexes={n:c.n+i for i,n in enumerate(extnames)}
        for sn,sec in enumerate(c.sections[1:],1):
            if sn in remove[oi]:
                struct.pack_into('<I',d,20+(sn-1)*40+36,(sec['flags']|0x800)&~0x1000)
                continue
            rp=struct.unpack_from('<I',d,20+(sn-1)*40+24)[0]
            for j,(off,ti,kind) in enumerate(sec['relocs']):
                if ti in redirects[oi]:struct.pack_into('<I',d,rp+j*10+4,extindexes[redirects[oi][ti]])
        path.write_bytes(d)
        added=[(n,0,0) for n in extnames]+list(set(additions[oi]))
        if added:append_symbols(path,path,added)
    summary=dict(duplicate_events=len(events),duplicate_symbols=len(report),identical_symbols=sum(r['identical'] for r in report),
                 differing_symbols=sum(not r['identical'] for r in report),objects_changed=len(set(changes)|set(remove)))
    dump(out/'comdat_comparison.json',report);dump(out/'comdat_comparison_summary.json',summary)
    return summary


def source_side_report(db,objects,out):
    """Attach source-unit provenance to every outstanding source reconciliation."""
    import placelink as place
    units=place.load_recipe(TREE)
    context=[dict(unit=i,source=u['source'],object=objects[i].name) for i,u in enumerate(units)]
    byobject={r['object']:r for r in context}
    dump(out/'unit_context.json',context)
    live={n for n, in db.execute('SELECT name FROM live_name')}
    conflicts=[]
    for name, in db.execute('SELECT name FROM binding GROUP BY name HAVING COUNT(DISTINCT address)>1'):
        occurrences=[dict(address=hx(a),**context[oi]) for a,oi in db.execute('SELECT address,unit FROM binding WHERE name=? ORDER BY address,unit',(name,))]
        conflicts.append(dict(symbol=name,reachable=name in live,addresses=sorted({r['address'] for r in occurrences}),units=occurrences))
    dump(out/'binding_conflicts.json',conflicts)
    unmapped=json.loads((out/'unmapped_addresses.json').read_text())
    for row in unmapped:
        a=int(row['address'],16)
        row['units']=[dict(symbol=n,reachable=n in live or label(a) in live,**context[oi]) for n,oi in db.execute('SELECT name,unit FROM binding WHERE address=? ORDER BY unit,name',(a,))]
        row['reachable']=any(r['reachable'] for r in row['units'])
    dump(out/'unmapped_addresses.json',unmapped)
    comparison=json.loads((out/'comdat_comparison.json').read_text()) if (out/'comdat_comparison.json').exists() else []
    for row in comparison:
        for d in row['definitions']:
            d['source']=context[d['unit']]['source']
            d['matched_addresses']=[hx(lo+d['offset']-offset) for lo,hi,offset in db.execute(
                'SELECT lo,hi,offset FROM span WHERE unit=? AND section=? AND offset<=? AND offset+(hi-lo)>?',
                (d['unit'],d['section'],d['offset'],d['offset']))]
            d['address_evidence']='matched_span' if d['matched_addresses'] else 'recipe_binding_only' if d['addresses'] else 'unmatched_copy_without_address'
    dump(out/'comdat_comparison.json',comparison)
    collisions=[r for r in comparison if not r['identical']]
    unresolved=json.loads((out/'native_unresolved.json').read_text())
    for row in unresolved:
        name=row['symbol']
        row['units']=[byobject[o] for o in row['objects'] if o in byobject]
        row['bindings']=[dict(address=hx(a),**context[oi]) for a,oi in db.execute('SELECT address,unit FROM binding WHERE name=?',(name,))]
        row['matched_reference_units']=[context[oi] for oi, in db.execute('SELECT unit FROM matched_reference WHERE name=?',(name,))]
    dump(out/'native_unresolved.json',unresolved)
    issues=[]
    for kind,detail in db.execute("SELECT kind,detail FROM issue WHERE kind NOT IN ('runtime_abi','compiler_data_owner')"):
        d=json.loads(detail)
        if 'unit' in d:d.update(context[d['unit']])
        issues.append(dict(kind=kind,**d))
    with (out/'blockers.jsonl').open('w',encoding='utf-8') as f:
        for r in issues+[dict(kind='binding_conflict',**r) for r in conflicts]+[dict(kind='COMDAT_source_naming_collision',**r) for r in collisions]+[dict(kind='native_unresolved',**r) for r in unresolved]:
            f.write(json.dumps(r)+'\n')
    warnings=Counter()
    for detail, in db.execute('SELECT detail FROM alias'):
        d=json.loads(detail)
        if d.get('abi_warning') in ('mismatch','unverified','unverified_runtime_abi'):warnings[d['abi_warning']]+=1
    summary=dict(binding_conflicts=len(conflicts),reachable_binding_conflicts=sum(r['reachable'] for r in conflicts),
        unreachable_binding_conflicts=sum(not r['reachable'] for r in conflicts),unmapped_addresses=unmapped,
        differing_comdat_symbols=len(collisions),native_unresolved=len(unresolved),abi_warnings=dict(warnings))
    dump(out/'source_side_summary.json',summary)
    allbound={n for n, in db.execute('SELECT DISTINCT name FROM binding')}
    totals=Counter();remaining=[];constant_names=set();mutable_names=set();startup=[]
    for oi,path in enumerate(objects):
        c=CoffView(out/'objects'/path.name)
        for sn,s in enumerate(c.sections[1:],1):
            if not s['flags']&0x800 and s['name'].startswith(('.CRT$XC','.CRT$XI','.CRT$XT')):
                startup.append(dict(**context[oi],section=sn))
        for t in c.symbols.values():
            if t['section']<=0 or t['storage']!=2:continue
            sec=c.sections[t['section']]
            if sec['flags']&0x820 or sec['name'].startswith('.debug'):continue
            mutable=bool(sec['flags']&0x80000000)
            totals['live_mutable_definition_occurrences' if mutable else 'live_constant_definition_occurrences']+=1
            (mutable_names if mutable else constant_names).add(t['name'])
            if t['name'] in allbound:remaining.append(dict(**context[oi],symbol=t['name'],section=t['section'],mutable=mutable))
    totals.update(live_constant_unique_symbols=len(constant_names),live_mutable_unique_symbols=len(mutable_names),
        retained_recipe_bound_compiler_definitions=len(remaining),remaining_compiler_startup_sections=len(startup))
    dump(out/'final_ownership_totals.json',dict(counts=totals,retained_recipe_bound_compiler_definitions=remaining,
        startup_sections=startup,passed=not remaining and not startup))
    return summary
