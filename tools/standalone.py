from bisect import bisect_left
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

import placelink as place
from standalone_common import (BASE,IMAGE,OUT,TC,TREE,PE,append_symbols,database,
                               dump,hx,issue,label,reserve,spans,archive_symbols,archive_imports)


def tool(name,args,out,env):
    reserve(192*1024**2)
    with Path(out).open('wb') as log:
        p=subprocess.Popen([str(TC/'VC/bin'/name)]+args,env=env,stdout=log,stderr=subprocess.STDOUT,
                           creationflags=0x08000000,cwd=OUT)
        low=False
        while p.poll() is None:
            if place.available_memory()<place.RESERVE:
                subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'],capture_output=True,creationflags=0x08000000)
                low=True;break
            time.sleep(.2)
        rc=p.wait()
    if low:raise RuntimeError('free RAM fell below 3 GiB; stopped '+name)
    return rc


def setup(db,units):
    for table in ('binding','definition','reference','weak','resolved_weak','span','address','import','issue','alias'):
        db.execute('DELETE FROM '+table)
    db.execute('CREATE TABLE IF NOT EXISTS binding_proof(name TEXT,address INTEGER,unit INTEGER,site INTEGER,kind INTEGER,PRIMARY KEY(name,address,unit,site))')
    db.execute('DELETE FROM binding_proof')
    for i,u in enumerate(units):
        for n,a in u.get('symbols',{}).items():
            db.execute('INSERT OR IGNORE INTO binding VALUES (?,?,?)',(n,int(a,0),i))
        for f in u['functions']:
            for n in [f['symbol']]+f.get('fold_aliases',[]):
                db.execute('INSERT OR IGNORE INTO binding VALUES (?,?,?)',(n,int(f['address'],16),i))
    db.commit()


def index_objects(db,units,objects,pe,out):
    """Current COFF records, compiler interior spans, proven relocation inference.

    Inferred names are accepted only from an exact compiled function extent, and
    must agree across every use. No stale symbol/classification inventory drives
    link decisions. The old inventories remain useful comparison baselines.
    """
    sys.path.insert(0,str(TREE/'tools'))
    from compare import Coff
    highlow=dict(pe.relocations());highlow_sites=sorted(highlow);count=Counter();data_candidates={}
    accepted_eh=json.loads((out/'accepted_eh.json').read_text()) if (out/'accepted_eh.json').exists() else {}
    accepted_eh={int(k):set(map(tuple,v)) for k,v in accepted_eh.items()}
    for oi,(u,path) in enumerate(zip(units,objects)):
        if oi%100==0:
            reserve(32*1024**2)
            print('Index %d/%d; %.2f GiB free'%(oi,len(units),place.available_memory()/2**30),flush=True)
        c=Coff(path);local={n:int(a,0) for n,a in u.get('symbols',{}).items()}
        locations=defaultdict(list);candidates=defaultdict(set)
        for f in u['functions']:
            sy=c.named(f['symbol']);a=int(f['address'],16)
            locations[sy['section']].append((sy['value'],sy['value']+f['size'],a,f['symbol'],'function'))
            for n in [f['symbol']]+f.get('fold_aliases',[]):local[n]=a
        # Locate EH sections and their scattered pieces using the same anchors
        # as the phase-one matcher, retaining only exact masked-byte matches.
        anchors={};xdata={}
        for sn,ll in list(locations.items()):
            sec=c.sections[sn]
            for off,ti,kind in sec['relocs']:
                t=c.symbols[ti]
                if t['section']<=0 or not c.sections[t['section']]['name'].startswith('.text$x'):continue
                owner=next((x for x in ll if x[0]<=off and off+4<=x[1]),None)
                if owner is None or kind not in (6,20):continue
                ov=struct.unpack('<I' if kind==6 else '<i',pe.read(owner[2]+off-owner[0],4))[0]
                if kind==20:ov+=owner[2]+off-owner[0]+4
                av=struct.unpack_from('<I' if kind==6 else '<i',sec['data'],off)[0]
                base=(ov-av-t['value'])&0xffffffff
                if t['section'] in anchors and anchors[t['section']]!=base:
                    issue(db,'conflicting_EH_anchor',unit=oi,section=t['section']);continue
                anchors[t['section']]=base
        for sn,base in anchors.items():
            for off,ti,kind in c.sections[sn]['relocs']:
                t=c.symbols[ti]
                if kind==6 and t['section']>0 and c.sections[t['section']]['name'].startswith('.xdata'):
                    ov=struct.unpack('<I',pe.read(base+off,4))[0]
                    av=struct.unpack_from('<I',c.sections[sn]['data'],off)[0]
                    xdata[t['section']]=(ov-av-t['value'])&0xffffffff
        for sn,base in anchors.items():
            sec=c.sections[sn];where={}
            cuts=sorted({0,len(sec['data'])}|{s['value'] for s in c.symbols.values() if s['section']==sn})
            for xn,xb in xdata.items():
                for off,ti,kind in c.sections[xn]['relocs']:
                    t=c.symbols[ti]
                    if kind==6 and t['section']==sn:
                        av=struct.unpack_from('<I',c.sections[xn]['data'],off)[0]
                        where[t['value']+av]=struct.unpack('<I',pe.read(xb+off,4))[0]
            for s0,s1 in zip(cuts,cuts[1:]):
                if s0>=s1:continue
                at=where.get(s0,base+s0)
                if (at,s1-s0) not in accepted_eh.get(oi,set()):continue
                try:original=pe.read(at,s1-s0)
                except ValueError:continue
                mask={j for off,ti,k in sec['relocs'] if s0<=off<s1 for j in range(off-s0,off-s0+4)}
                if any(x!=y for j,(x,y) in enumerate(zip(sec['data'][s0:s1],original)) if j not in mask):continue
                locations[sn].append((s0,s1,at,'<EH>','eh'))
        for sn,ll in locations.items():
            sec=c.sections[sn]
            for lo,hi,a,name,kind in ll:
                original=pe.read(a,hi-lo);data=sec['data'][lo:hi]
                mask={j for off,ti,k in sec['relocs'] if lo<=off<hi for j in range(off-lo,off-lo+4)}
                if len(data)!=hi-lo or any(x!=y for j,(x,y) in enumerate(zip(data,original)) if j not in mask):
                    issue(db,'compiler_byte_mismatch',unit=oi,address=hx(a),symbol=name);continue
                db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(a,a+hi-lo,oi,sn,lo,name,kind))
                count[kind+'_spans']+=1
                relsites={off for off,ti,k in sec['relocs'] if k in (6,7,20,11)}
                for site in highlow_sites[bisect_left(highlow_sites,a):bisect_left(highlow_sites,a+hi-lo)]:
                    target=highlow[site]
                    if a<=site and site+4<=a+hi-lo and site-a+lo not in relsites:
                        value=struct.unpack_from('<I',sec['data'],site-a+lo)[0]
                        if value==target:
                            issue(db,'hardcoded_HIGHLOW_operand',unit=oi,source=u['source'],
                                  address=hx(site),target=hx(target),symbol=name)
                            count['hardcoded_HIGHLOW_operands']+=1
                for off,ti,kind in sec['relocs']:
                    if not lo<=off or off+4>hi or kind not in (6,7,11,20):continue
                    t=c.symbols[ti]
                    ov=struct.unpack('<I' if kind!=20 else '<i',pe.read(a+off-lo,4))[0]
                    if kind==20:ov+=a+off-lo+4
                    if kind==7:ov+=pe.base
                    if kind==11:
                        template=next(s for s in pe.sections if s['name']=='.tls')
                        ov+=template['lo']
                    av=struct.unpack_from('<I' if kind!=20 else '<i',sec['data'],off)[0]
                    target=(ov-av)&0xffffffff
                    if t['storage'] in (2,105):
                        if t['name'] in local and local[t['name']]!=target:
                            issue(db,'relocation_binding_mismatch',unit=oi,symbol=t['name'],
                                  recipe=hx(local[t['name']]),observed=hx(target))
                        db.execute('INSERT OR IGNORE INTO binding VALUES (?,?,?)',(t['name'],target,oi))
                        db.execute('INSERT OR IGNORE INTO binding_proof VALUES (?,?,?,?,?)',(t['name'],target,oi,a+off-lo,kind))
                    if t['section']>0 and not c.sections[t['section']]['flags']&0x20:
                        candidates[t['section']].add((target-t['value'])&0xffffffff)
        for s in c.symbols.values():
            if s['storage'] in (2,105):
                if s['section']>0 or s['section']==-1:
                    flags=c.sections[s['section']]['flags'] if s['section']>0 else 0
                    db.execute('INSERT OR IGNORE INTO definition VALUES (?,?,?,?,?,?)',
                        (s['name'],oi,s['section'],s['value'],bool(flags&0x1000),bool(flags&0x20)))
                elif s['section']==0:
                    db.execute('INSERT OR IGNORE INTO reference VALUES (?,?)',(s['name'],oi))
            if s['section']>0 and s['name'] in local and not c.sections[s['section']]['flags']&0x20:
                candidates[s['section']].add(local[s['name']]-s['value'])
        ptr,total=struct.unpack_from('<II',c.data,8)
        for ix,s in c.symbols.items():
            if s['storage']==105:
                fallback,search=struct.unpack_from('<II',c.data,ptr+(ix+1)*18)
                db.execute('INSERT INTO weak VALUES (?,?,?,?)',(s['name'],c.symbols[fallback]['name'],search,oi))
        data_candidates[oi]={sn:sorted(v) for sn,v in candidates.items()}
        db.commit()
    dump(out/'data_candidates.json',data_candidates)
    resolve_weak(db)
    dump(out/'index_report.json',dict(count));return data_candidates


def resolve_weak(db):
    db.execute('DELETE FROM resolved_weak')
    changed=True
    while changed:
        old=db.total_changes
        db.execute('''INSERT OR IGNORE INTO resolved_weak
          SELECT DISTINCT w.name FROM weak w WHERE w.search IN (1,2,3) AND
          (EXISTS(SELECT 1 FROM definition d WHERE d.name=w.fallback) OR
           EXISTS(SELECT 1 FROM resolved_weak r WHERE r.name=w.fallback))''')
        changed=db.total_changes>old
    db.commit()


def reconcile_data(db,units,objects,pe,candidates,out):
    """Use original storage for proven data; rewrite only build copies of COFF.

    The complete original-data fallback avoids holes from stale inventories.
    Every discarded compiler data section must match bytes and pointer identity.
    Residual bound writable identities are passed to the approved ownership
    policy, which drops their compiler definitions in the private build copies.
    """
    sys.path.insert(0,str(TREE/'tools'));from compare import Coff
    plans={};stats=Counter()
    globalmap={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding GROUP BY name HAVING COUNT(DISTINCT address)=1')}
    for oi,(u,path) in enumerate(zip(units,objects)):
        c=Coff(path);cc=candidates.get(oi,candidates.get(str(oi),{}));local={n:int(a,0) for n,a in u.get('symbols',{}).items()}
        for f in u['functions']:
            local[f['symbol']]=int(f['address'],16)
        accepted={};observed={}
        for ss,bb in cc.items():
            sn=int(ss);sec=c.sections[sn]
            if len(bb)!=1 or not sec['data']:continue
            base=bb[0];s=pe.section(base)
            if s is None or s['name'] not in ('.data','.rdata','.tls','CONST') or base+len(sec['data'])>s['hi']:continue
            try:original=pe.read(base,len(sec['data']))
            except ValueError:continue
            mask={j for off,ti,k in sec['relocs'] for j in range(off,off+4)}
            if any(a!=b for j,(a,b) in enumerate(zip(sec['data'],original)) if j not in mask):continue
            syms=[t for t in c.symbols.values() if t['section']==sn]
            if any((local.get(t['name'],globalmap.get(t['name'],base+t['value'])) != base+t['value']) for t in syms):continue
            observed[sn]=(base,original)
        changed=True
        while changed:
            changed=False
            for sn,(base,original) in observed.items():
                if sn in accepted:continue
                ok=True
                for off,ti,kind in c.sections[sn]['relocs']:
                    t=c.symbols[ti]
                    if kind!=6 or off+4>len(original):ok=False;break
                    target=local.get(t['name'],globalmap.get(t['name']))
                    if target is None and t['section'] in accepted:target=accepted[t['section']]+t['value']
                    if target is None and t['section']==sn:target=base+t['value']
                    if target is None and t['section']==-1:target=t['value']
                    if target is None:
                        owner=db.execute('SELECT lo,offset FROM span WHERE unit=? AND section=? AND offset<=? AND offset+(hi-lo)>? LIMIT 1',
                            (oi,t['section'],t['value'],t['value'])).fetchone()
                        if owner:target=owner[0]+t['value']-owner[1]
                    addend=struct.unpack_from('<I',c.sections[sn]['data'],off)[0]
                    if target is None or (target+addend)&0xffffffff!=struct.unpack_from('<I',original,off)[0]:ok=False;break
                if ok:accepted[sn]=base;changed=True
        for sn,base in accepted.items():
            for t in c.symbols.values():
                if t['section']==sn:
                    db.execute('INSERT OR IGNORE INTO address VALUES (?,?)',(base+t['value'],'data_canonical'))
                if t['section']==sn and t['storage']==2:
                    db.execute('DELETE FROM definition WHERE unit=? AND name=? AND section=?',(oi,t['name'],sn))
                    db.execute('INSERT OR IGNORE INTO reference VALUES (?,?)',(t['name'],oi))
                    db.execute('INSERT OR IGNORE INTO binding VALUES (?,?,?)',(t['name'],base+t['value'],oi))
            stats['canonicalized_sections']+=1;stats['canonicalized_bytes']+=len(c.sections[sn]['data'])
        for sn,sec in enumerate(c.sections[1:],1):
            if sn in accepted:continue
            if sec['name'].startswith('.tls') and sec['data']:
                issue(db,'unreconciled_TLS_section',unit=oi,section=sn,size=len(sec['data']))
            if sec['flags']&0x20 or not sec['data']:continue
            syms=[t for t in c.symbols.values() if t['section']==sn and t['storage']==2]
            for t in syms:
                a=local.get(t['name'],globalmap.get(t['name']))
                if a is not None and pe.section(a) and pe.section(a)['name'] in ('.data','.tls'):
                    issue(db,'unproved_mutable_data_identity',unit=oi,symbol=t['name'],address=hx(a),section=sn)
                    stats['unproved_mutable_data_symbols']+=1
        plans[oi]=accepted
        if oi%100==0:db.commit()
    db.commit();dump(out/'data_reconciliation.json',dict(stats));dump(out/'object_rewrite_plan.json',plans)
    return plans


def imports(db,pe,out,env):
    """Use SDK import symbols when present; custom ordinal/name import libraries otherwise."""
    iat=pe.imports();bydll=defaultdict(list)
    for a,value in iat.items():
        dll,export=value.split('!',1);bydll[dll].append((a,export))
    libs=[];report=[]
    for dll,entries in bydll.items():
        sdk=TC/'SDK/Lib'/(Path(dll).stem+'.lib')
        available=set()
        sdk_imports={}
        if sdk.exists():
            available={n for n in archive_symbols(sdk) if n.startswith('__imp_')}
            sdk_imports=archive_imports(sdk)
            libs.append(str(sdk))
        custom=[]
        for a,export in entries:
            candidates=[]
            if (dll.lower(),export) in sdk_imports:
                candidates=[sdk_imports[dll.lower(),export]]
            elif not export.startswith('#'):
                for sym in available:
                    plain=sym[len('__imp_'):]
                    normalized=re.sub(r'@\d+$','',plain.lstrip('_@'))
                    if normalized==export or plain==export:candidates.append(sym)
            if len(candidates)==1:
                symbol=candidates[0]
                if str(sdk) not in libs:libs.append(str(sdk))
            else:
                symbolname=('fnv_ordinal_%08x'%a) if export.startswith('#') else export
                symbol=None
                custom.append((a,export,symbolname))
            db.execute('INSERT OR REPLACE INTO import VALUES (?,?,?,?)',(a,dll,export,symbol))
        if custom:
            lib=out/(Path(dll).stem+'_imports.lib');definition=lib.with_suffix('.def')
            export_lines=[]
            for a,export,symbolname in custom:
                export_lines.append('  '+symbolname+(' @'+export[1:]+' NONAME' if export.startswith('#') else ''))
            content='LIBRARY "'+dll+'"\nEXPORTS\n'+'\n'.join(export_lines)+'\n'
            same=definition.exists() and definition.read_text()==content
            reusable=same and lib.exists() and lib.stat().st_mtime>=definition.stat().st_mtime
            if not reusable:
                definition.write_text(content,encoding='ascii')
                if lib.exists():lib.unlink()
                rc=tool('lib.exe',['/nologo','/machine:x86','/out:'+str(lib),'/def:'+str(definition)],lib.with_suffix('.log'),env)
                if rc:raise RuntimeError('failed to make import library for '+dll)
            names={n for n in archive_symbols(lib) if n.startswith('__imp_')}
            for a,export,symbolname in custom:
                matches=names & {'__imp_'+symbolname,'__imp__'+symbolname}
                if len(matches)!=1:raise ValueError('ambiguous generated import name: '+symbolname)
                db.execute('UPDATE import SET symbol=? WHERE address=?',(matches.pop(),a))
            libs.append(str(lib))
        report.append(dict(dll=dll,imports=len(entries),sdk_library=str(sdk) if available else None,custom_imports=len(custom)))
    db.commit();dump(out/'imports_report.json',dict(dlls=report,libraries=libs,slots=len(iat)))
    return libs


def canonical_tls(db,objects,pe,out):
    """Bind TLS symbols individually: source padding layouts are not ownership.

    Different units can each emit a full padding struct or duplicate views of
    one original TLS slot. Keeping those contributions would change SECREL
    offsets. Original operands plus their COFF addends prove each symbol's
    template offset without relying on the aggregate compiler layout.
    """
    sys.path.insert(0,str(TREE/'tools'));from compare import Coff
    template=next((s for s in pe.sections if s['name']=='.tls'),None)
    if template is None:return {}
    globalmap={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding GROUP BY name HAVING COUNT(DISTINCT address)=1')}
    plans={};counts=Counter();successful=set()
    for oi,path in enumerate(objects):
        c=Coff(path);sections={sn for sn,sec in enumerate(c.sections[1:],1) if sec['name'].startswith('.tls')}
        # Discover effective fields before image generation, including external
        # and private TLS views in units that emit no TLS contribution at all.
        for lo,hi,sn,start in db.execute('SELECT lo,hi,section,offset FROM span WHERE unit=?',(oi,)):
            for off,ti,kind in c.sections[sn]['relocs']:
                if kind!=11 or not start<=off or off+4>start+hi-lo:continue
                a=(template['lo']+struct.unpack('<I',pe.read(lo+off-start,4))[0])&0xffffffff
                if not template['lo']<=a<template['hi']:raise ValueError('matched SECREL field outside TLS template')
                before=db.total_changes
                db.execute('INSERT OR IGNORE INTO address VALUES (?,?)',(a,'tls_effective_field'))
                counts['effective_fields_discovered']+=db.total_changes-before
        if not sections:continue
        evidence=defaultdict(set)
        local={n:a for n,a in db.execute('SELECT name,MIN(address) FROM binding WHERE unit=? GROUP BY name HAVING COUNT(DISTINCT address)=1',(oi,))}
        for ix,t in c.symbols.items():
            if t['section'] in sections:
                a=local.get(t['name'],globalmap.get(t['name']))
                if a is not None and template['lo']<=a<template['hi']:evidence[ix].add(a)
        for lo,hi,sn,offset in db.execute('SELECT lo,hi,section,offset FROM span WHERE unit=?',(oi,)):
            sec=c.sections[sn]
            for off,ti,kind in sec['relocs']:
                if c.symbols[ti]['section'] not in sections or kind not in (6,11) or not offset<=off or off+4>offset+hi-lo:continue
                observed=struct.unpack('<I',pe.read(lo+off-offset,4))[0]
                if kind==11:observed+=template['lo']
                addend=struct.unpack_from('<I',sec['data'],off)[0]
                evidence[ti].add((observed-addend)&0xffffffff)
        mapped={ix:next(iter(aa)) for ix,aa in evidence.items() if len(aa)==1 and template['lo']<=next(iter(aa))<template['hi']}
        missing=set()
        for sn,sec in enumerate(c.sections[1:],1):
            if sn in sections:continue
            for off,ti,kind in sec['relocs']:
                if c.symbols[ti]['section'] in sections and ti not in mapped:missing.add(ti)
        for ti in missing:
            issue(db,'unmapped_TLS_symbol',unit=oi,symbol=c.symbols[ti]['name'],
                  evidence=[hx(a) for a in sorted(evidence[ti])])
        for ix,t in c.symbols.items():
            if t['section'] not in sections:continue
            if t['storage']==2:
                db.execute('DELETE FROM definition WHERE unit=? AND name=? AND section=?',(oi,t['name'],t['section']))
                if ix in mapped:
                    db.execute('INSERT OR IGNORE INTO reference VALUES (?,?)',(t['name'],oi))
                    db.execute('INSERT OR IGNORE INTO binding VALUES (?,?,?)',(t['name'],mapped[ix],oi))
            if ix in mapped:
                db.execute('INSERT OR IGNORE INTO address VALUES (?,?)',(mapped[ix],'tls'))
        plans[oi]=dict(sections=sorted(sections),symbols=mapped)
        counts['sections_replaced']+=len(sections);counts['symbols_mapped']+=len(mapped);counts['unmapped_referenced_symbols']+=len(missing)
        if not missing:successful.add(oi)
    # Remove only the aggregate-layout warning superseded by this symbol-level
    # proof, preserving any actual unresolved symbol evidence above.
    for rowid,kind,detail in list(db.execute("SELECT rowid,kind,detail FROM issue WHERE kind IN ('unreconciled_TLS_section','unproved_mutable_data_identity')")):
        d=json.loads(detail)
        if d['unit'] in successful and (kind=='unreconciled_TLS_section' or template['lo']<=int(d.get('address','0'),16)<template['hi']):
            db.execute('DELETE FROM issue WHERE rowid=?',(rowid,))
    db.commit();dump(out/'tls_reconciliation.json',dict(counts));dump(out/'tls_rewrite_plan.json',plans)
    return plans


def rewrite_objects(db,objects,plans,out,tls_plans=None,policy_plans=None):
    sys.path.insert(0,str(TREE/'tools'));from compare import Coff
    allspans,find=spans(db);labels=defaultdict(list)
    for a, in db.execute('SELECT address FROM address ORDER BY address'):
        owner=find(a)
        if owner:labels[owner[2]].append((label(a),owner[3],owner[4]+a-owner[0]))
    folder=out/'objects';folder.mkdir(exist_ok=True);result=[]
    for oi,path in enumerate(objects):
        dest=folder/path.name
        append_symbols(path,dest,labels[oi])
        plan=plans.get(oi,plans.get(str(oi),{}))
        tls=(tls_plans or {}).get(oi,{})
        policy=(policy_plans or {}).get(oi,{})
        targets=policy.get('symbols',{})
        unresolved=policy.get('unresolved',{})
        removed={int(sn) for sn in plan}|set(tls.get('sections',[]))|set(policy.get('sections',[]))|set(policy.get('startup',[]))
        if removed or targets or unresolved:
            c=Coff(dest);data=bytearray(c.data);ptr,n=struct.unpack_from('<II',data,8)
            strings=bytearray(data[ptr+n*18:]);extra=bytearray();added={}
            def external(name):
                if name in added:return added[name]
                ix=n+len(extra)//18;added[name]=ix
                raw=struct.pack('<II',0,len(strings));strings.extend(name.encode()+b'\0')
                extra.extend(struct.pack('<8sIhHBB',raw,0,0,0,2,0));return ix
            for sn in removed:
                flags=struct.unpack_from('<I',data,20+(sn-1)*40+36)[0]
                struct.pack_into('<I',data,20+(sn-1)*40+36,(flags|0x800)&~0x1000)
                for ix,t in c.symbols.items():
                    if t['section']==sn and t['storage']==3 and c.data[ptr+ix*18+17]:
                        # A discarded COMDAT must cease to advertise a COMDAT
                        # key after its external definition becomes an alias.
                        data[ptr+(ix+1)*18+14]=0
                        struct.pack_into('<h',data,ptr+(ix+1)*18+12,0)
                for ix,t in c.symbols.items():
                    if t['section']==sn and t['storage']==2:
                        struct.pack_into('<Ih',data,ptr+ix*18+8,0,0)
            for ix in set(targets)|set(unresolved):
                if c.symbols[ix]['storage']==2:
                    struct.pack_into('<Ih',data,ptr+ix*18+8,0,0)
            for sn,sec in enumerate(c.sections[1:],1):
                if sn in removed:continue
                relptr=struct.unpack_from('<I',data,20+(sn-1)*40+24)[0]
                for j,(off,ti,kind) in enumerate(sec['relocs']):
                    t=c.symbols[ti];base=plan.get(t['section'],plan.get(str(t['section'])))
                    if ti in unresolved:
                        entry=unresolved[ti];ix=external(entry['name'])
                        struct.pack_into('<I',data,relptr+j*10+4,ix)
                        if entry['delta']:
                            rawptr=struct.unpack_from('<I',data,20+(sn-1)*40+20)[0]
                            addend=struct.unpack_from('<I',data,rawptr+off)[0]
                            struct.pack_into('<I',data,rawptr+off,(addend+entry['delta'])&0xffffffff)
                        continue
                    target=targets.get(ti)
                    if t['section'] in tls.get('sections',[]):target=tls.get('symbols',{}).get(ti)
                    if base is None and target is None:continue
                    # Preserve any existing COFF addend; the new target denotes
                    # the exact old symbol location, including static interiors.
                    address=target if target is not None else base+t['value']
                    imported=db.execute('SELECT symbol FROM import WHERE address=?',(address,)).fetchone()
                    ix=external(imported[0] if imported else label(address))
                    struct.pack_into('<I',data,relptr+j*10+4,ix)
            struct.pack_into('<I',strings,0,len(strings));struct.pack_into('<I',data,12,n+len(extra)//18)
            dest.write_bytes(data[:ptr+n*18]+extra+strings)
        result.append(dest)
    return result


def current_blockers(db,out):
    duplicate=[]
    for n,count in db.execute('''SELECT name,COUNT(*) FROM definition WHERE comdat=0
                               GROUP BY name HAVING COUNT(*)>1'''):
        duplicate.append(dict(symbol=n,definitions=count))
    dump(out/'duplicate_symbols.json',duplicate)
    conflicts=[dict(symbol=n,addresses=[hx(int(a)) for a in aa.split(',')]) for n,aa in db.execute(
        'SELECT name,GROUP_CONCAT(DISTINCT address) FROM binding GROUP BY name HAVING COUNT(DISTINCT address)>1')]
    dump(out/'binding_conflicts.json',conflicts)
    counts=dict(db.execute('SELECT kind,COUNT(*) FROM issue GROUP BY kind'))
    with (out/'blockers.jsonl').open('w',encoding='utf-8') as f:
        for kind,detail in db.execute("SELECT kind,detail FROM issue WHERE kind NOT IN ('runtime_abi','compiler_data_owner')"):
            f.write(json.dumps(dict(kind=kind,**json.loads(detail)))+'\n')
    result=dict(duplicates=len(duplicate),binding_conflicts=len(conflicts),issues=counts,
                aliases=dict(db.execute('SELECT status,COUNT(*) FROM alias GROUP BY status')))
    dump(out/'blockers_summary.json',result);return result


def link(objects,libs,pe,out,env,iat_symbols=()):
    candidate=out/'FalloutNV.candidate.exe'
    # Remove only this tool's stale candidate; never let a previous successful
    # output masquerade as the result of a failed current link.
    if candidate.exists():candidate.unlink()
    args=['/NOLOGO','/MACHINE:X86','/SUBSYSTEM:WINDOWS','/BASE:0x400000',
          '/LARGEADDRESSAWARE' if pe.characteristics&0x20 else '/LARGEADDRESSAWARE:NO',
          '/INCREMENTAL:NO','/OPT:NOICF','/OPT:REF','/NODEFAULTLIB','/DYNAMICBASE:NO',
          '/FIXED:NO','/NXCOMPAT:NO','/SAFESEH:NO','/MANIFEST:NO',
          '/ENTRY:'+label(pe.entry).lstrip('_'),'/OUT:'+str(candidate),'/MAP:'+str(out/'FalloutNV.map')]
    from pe_headers import linker_options
    options=linker_options(pe);replaced={x.split(':',1)[0] for x in options}
    args=[x for x in args if x.split(':',1)[0] not in replaced]+options
    # Generated original data contains the original init tables; retaining these
    # sections roots their function relocations as well as the TLS callback array.
    args+=['/INCLUDE:'+n for n in sorted(set(iat_symbols))]
    args+=['/INCLUDE:__tls_used'] if pe.directory(9)[0] else []
    args+=['/INCLUDE:'+label(int(a,16)) for a in json.loads((out/'image_report.json').read_text())['tls_callbacks']]
    data=json.loads((out/'data/data_objects.json').read_text())
    args+=list(map(str,objects))+[str(out/n) for n in ('aliases.obj','image_code.obj','image_resources.obj') if (out/n).exists()]+data+libs
    rsp=out/'link.rsp';rsp.write_text('\n'.join('"'+a+'"' for a in args)+'\n',encoding='ascii')
    rc=tool('link.exe',['@'+str(rsp)],out/'link.log',env)
    errors=Counter()
    for l in (out/'link.log').read_text(errors='replace').splitlines():
        m=re.search(r'(?:fatal )?error (LNK\d+)',l)
        if m:errors[m[1]]+=1
    result=dict(returncode=rc,errors=dict(errors),candidate_exists=candidate.exists())
    dump(out/'link_report.json',result);return result


def native_diagnostics(db,out):
    duplicates=[];unresolved={}
    def symbol(text):
        m=re.search(r'\(([^()]*)\)$',text)
        return m[1] if m else text.strip(' "')
    for line in (out/'link.log').read_text(errors='replace').splitlines():
        m=re.match(r'(.+?) : error LNK2005: (.+) already defined in (.+)',line)
        if m:
            name=symbol(m[2]);comdat=db.execute('SELECT MAX(comdat) FROM definition WHERE name=?',(name,)).fetchone()[0]
            duplicates.append(dict(symbol=name,object=m[1],previous_object=m[3],comdat=bool(comdat)))
        m=re.search(r'unresolved external symbol (.*?)(?: referenced in function|$)',line)
        if m:
            name=symbol(m[1]);entry=unresolved.setdefault(name,dict(symbol=name,objects=set()))
            entry['objects'].add(line.split(' : error ',1)[0])
    for name,row in unresolved.items():
        row['objects']=sorted(row['objects'])
        status=db.execute('SELECT status FROM alias WHERE name=?',(name,)).fetchone()
        row['alias_status']=status[0] if status else None
    summary=dict(duplicate_events=len(duplicates),distinct_duplicate_symbols=len({r['symbol'] for r in duplicates}),
                 duplicate_classes=dict(Counter('COMDAT identity' if r['comdat'] else 'strong definition' for r in duplicates)),
                 unique_unresolved=len(unresolved),
                 unresolved_generated_VA_labels=sorted(n for n in unresolved if n.startswith('_fnv_va_')),
                 unresolved_import_names=sorted(n for n in unresolved if n.startswith('__imp_')))
    dump(out/'native_duplicates.json',duplicates)
    dump(out/'native_unresolved.json',list(unresolved.values()))
    dump(out/'native_summary.json',summary)
    return summary


def verify_linked_highlow(db,original,actual,map_path,generated_objects=()):
    """Check final pointers, including address labels lost by native COMDAT selection.

    Unreferenced compiler spans may have disappeared under REF. Only sites whose
    final placement is proved by a public address label are inspected here.
    """
    symbols={}
    for line in Path(map_path).read_text(errors='replace').splitlines():
        m=re.match(r'\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8})\b',line)
        if m:symbols[m[1]]=int(m[2],16)
    # Generated fragments only label address targets, not every pointer site.
    # Recover interior source placements from the actual COFF DIR32 records.
    # Both original and linked section origins must agree across all anchors.
    from phase2_policy import CoffView
    generated_sites={}
    highlow=dict(original.relocations())
    for path in generated_objects:
        c=CoffView(Path(path))
        for sn,sec in enumerate(c.sections[1:],1):
            anchors=[(int(t['name'][-8:],16),t['value'],symbols.get(t['name']))
                     for t in c.symbols.values() if t['section']==sn
                     and re.fullmatch(r'_fnv_va_[0-9a-fA-F]{8}',t['name'])]
            origins={a-v for a,v,_ in anchors}
            linked={a-v for _,v,a in anchors if a is not None}
            if len(origins)!=1 or len(linked)!=1:continue
            origin=origins.pop();placed=linked.pop()
            for off,_,kind in sec['relocs']:
                site=origin+off
                if kind==6 and site in highlow:
                    at=placed+off
                    if site in generated_sites and generated_sites[site]!=at:
                        raise ValueError('Conflicting generated pointer placement: '+hx(site))
                    generated_sites[site]=at
    _,owner=spans(db);imports=dict(db.execute('SELECT address,symbol FROM import'))
    def mapped(address):
        if address in imports:return symbols.get(imports[address])
        if label(address) in symbols:return symbols[label(address)]
        if original.base<=address<original.base+original.header_size:return actual.base+address-original.base
        span=owner(address)
        if span and label(span[0]) in symbols:return symbols[label(span[0])]+address-span[0]
        return None
    checked=skipped=0;errors=[]
    for site,target in original.relocations():
        at=generated_sites.get(site,mapped(site))
        if at is None:skipped+=1;continue
        checked+=1;expected=mapped(target);value=struct.unpack('<I',actual.read(at,4))[0]
        if expected is None or value!=expected:
            errors.append(dict(site=hx(site),target=hx(target),linked_site=hx(at),actual=hx(value),
                               expected=hx(expected) if expected is not None else None,
                               cause='missing_final_target_label' if expected is None else 'wrong_final_target'))
    return dict(passed=not errors,checked=checked,unplaced_sites_skipped=skipped,errors=errors)


def static_checks(db,pe,out,linked):
    """Gate on mapping/identity/ABI plus actual final loader metadata."""
    ignored=('runtime_abi','compiler_data_owner')
    issues=Counter()
    deferred=[]
    for kind,detail in db.execute('SELECT kind,detail FROM issue WHERE kind NOT IN (?,?)',ignored):
        d=json.loads(detail)
        if kind=='unmapped_address':
            a=int(d['address'],16)
            used=db.execute('SELECT 1 FROM live_name WHERE name=? OR name IN (SELECT name FROM binding WHERE address=?) LIMIT 1',(label(a),a)).fetchone()
            if not used:deferred.append(dict(kind=kind,**d));continue
        if kind=='relocation_binding_mismatch':
            if not db.execute('SELECT 1 FROM live_name WHERE name=?',(d['symbol'],)).fetchone():
                deferred.append(dict(kind=kind,**d));continue
        issues[kind]+=1
    issues=dict(issues)
    alias_failures=db.execute("SELECT COUNT(*) FROM alias a JOIN live_name l ON l.name=a.name WHERE a.status NOT LIKE 'ok%'").fetchone()[0]
    native_unresolved=out/'native_unresolved.json'
    if native_unresolved.exists():
        # Explicit source ALTERNATENAME fallbacks can resolve names for which
        # this generator supplies no address alias. Use native resolution as
        # the final authority rather than vetoing a successful fallback.
        alias_failures=sum(bool(r.get('alias_status') and not r['alias_status'].startswith('ok'))
                           for r in json.loads(native_unresolved.read_text()))
    duplicate=db.execute('SELECT COUNT(*) FROM (SELECT name FROM definition WHERE comdat=0 GROUP BY name HAVING COUNT(*)>1)').fetchone()[0]
    conflicts=db.execute('SELECT COUNT(*) FROM (SELECT b.name FROM binding b JOIN live_name l ON l.name=b.name GROUP BY b.name HAVING COUNT(DISTINCT b.address)>1)').fetchone()[0]
    check=dict(link_clean=linked['returncode']==0 and not linked['errors'],
               generator_issues=issues,alias_failures=alias_failures,duplicate_symbols=duplicate,
               identity_conflicts=conflicts,unreachable_source_issues=deferred)
    generated=json.loads((out/'image_report.json').read_text())['counts']
    check['all_original_HIGHLOW_mapped']=bool(generated.get('HIGHLOW_sites_mapped')==generated['original_HIGHLOW_count']
                                            and generated.get('HIGHLOW_targets_mapped')==generated['original_HIGHLOW_count'])
    ownership=out/'final_ownership_totals.json'
    check['single_global_owner_and_no_compiler_startup']=ownership.exists() and json.loads(ownership.read_text())['passed']
    candidate=out/'FalloutNV.candidate.exe'
    if check['link_clean'] and candidate.exists():
        actual=PE(candidate)
        pointers=verify_linked_highlow(db,pe,actual,out/'FalloutNV.map',
            [out/n for n in ('image_data.obj','image_code.obj') if (out/n).exists()])
        dump(out/'final_highlow_checks.json',pointers)
        check['final_HIGHLOW_targets_correct']=pointers['passed']
        normalize=lambda s:s.split('!',1)[0].lower()+'!'+s.split('!',1)[1]
        expected=set(map(normalize,pe.imports().values()));found=set(map(normalize,actual.imports().values()))
        check['missing_imports']=sorted(expected-found)
        check['entry_present']=bool(actual.section(actual.entry) and actual.section(actual.entry)['name']=='.text')
        tls,n=actual.directory(9);oldtls,_=pe.directory(9)
        check['tls_directory_present']=bool(tls) if oldtls else True
        callbacks=[]
        if tls:
            start,end,index,cb,zero,chars=struct.unpack('<IIIIII',actual.read(tls,24))
            check['tls_template_mapped']=bool(actual.section(start) and actual.section(end-1) and actual.section(index))
            if cb:
                for i in range(65536):
                    a=struct.unpack('<I',actual.read(cb+i*4,4))[0]
                    if not a:break
                    callbacks.append(a)
        expected_callbacks=json.loads((out/'image_report.json').read_text())['tls_callbacks']
        check['tls_callbacks_present']=len(callbacks)==len(expected_callbacks) and all(actual.section(a) for a in callbacks)
    check['passed']=bool(check['link_clean'] and check['all_original_HIGHLOW_mapped'] and check['single_global_owner_and_no_compiler_startup'] and not issues and not alias_failures and not duplicate and not conflicts and
        not check.get('missing_imports') and check.get('entry_present',False) and check.get('tls_directory_present',False)
        and check.get('tls_callbacks_present',False) and check.get('tls_template_mapped',True) and check.get('final_HIGHLOW_targets_correct',False))
    dump(out/'static_checks.json',check);return check
