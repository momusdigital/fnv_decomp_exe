"""Export private image storage to C++ and compile without reopening the EXE.

The emitted sources contain game bytes. Keep them in the ignored local folder.
Pointer fields are symbolic DIR32 initializers, never numeric original VAs.
Interior public labels are added to compiler-proved field offsets, without
changing compiler bytes or relocations. Unknown layouts stay explicitly opaque.
"""
from bisect import bisect_left
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import struct
import subprocess
import sys
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit(a):
    from phase2_policy import CoffView
    from standalone_common import dump
    from config import LOCAL
    root = a.out.resolve()
    if not root.is_relative_to(LOCAL):
        raise ValueError('game-derived output must stay in the ignored local folder')
    root.mkdir(parents=True, exist_ok=True)
    c = CoffView(a.input); records=[]
    symbols = list(c.symbols.values())
    # Scalar decorations are type evidence. Conflicting declarations, pointers,
    # non-finite floating payloads and aggregate layouts remain opaque.
    declarations_by_address=defaultdict(dict)
    if a.state.exists():
        db=sqlite3.connect(a.state.resolve().as_uri()+'?mode=ro',uri=True)
        for name,address in db.execute('select distinct name,address from binding'):
            match=re.search(r'@@3([MNHI])A$',name)
            if match:declarations_by_address[address][name]=match[1]
        db.close()
    typed_addresses=sorted(address for address,names in declarations_by_address.items() if len(set(names.values()))==1)
    typed_records=[]
    for sn,sec in enumerate(c.sections[1:],1):
        if sec['name'] == '.drectve':
            continue
        if sec['name'] not in ('.rdata','.data','.bss','.tls','CONST'):
            raise ValueError('unexpected storage section '+sec['name'])
        origins={int(t['name'][-8:],16)-t['value'] for t in symbols
                 if t['section']==sn and t['name'].startswith('_fnv_va_')}
        if len(origins)!=1:raise ValueError('ambiguous original storage origin')
        origin=origins.pop()
        rels = sorted(sec['relocs']); pos=0
        while pos < sec['size']:
            end = min(sec['size'],pos+a.chunk)
            crossing = [off for off,_,_ in rels if off<end<off+4]
            if crossing:
                end = min(crossing) & ~15
            if end<=pos:
                raise ValueError('chunk too small for relocation')
            index=len(records); anchor='deexe_data_%04d'%index
            members=[]; values=[]; declarations=set(); refs={}; cursor=pos; part_rels=[]
            bss=not sec['raw']; raw=c.data[sec['raw']:sec['raw']+sec['size']] if not bss else b''
            def opaque(start,stop):
                if stop<=start:return
                cursor=start
                def bytes_field(lo,hi):
                    if lo==hi:return
                    members.append('  unsigned char b%08x[%d];'%(lo,hi-lo))
                    if not bss:values.append('  {'+','.join(str(x) for x in raw[lo:hi])+'}')
                first=bisect_left(typed_addresses,origin+start)
                for address in typed_addresses[first:bisect_left(typed_addresses,origin+stop)]:
                    names=declarations_by_address[address];code=next(iter(names.values()))
                    size=8 if code=='N' else 4;at=address-origin
                    if at<cursor or at+size>stop:continue
                    value=bytes(size) if bss else raw[at:at+size]
                    number=struct.unpack('<'+{'M':'f','N':'d','H':'i','I':'I'}[code],value)[0]
                    if code in ('M','N'):
                        if not math.isfinite(number):continue
                        literal=format(number,'.9g' if code=='M' else '.17g')
                        # VC9 rejects the rounded-up nine-digit FLT_MAX spelling
                        # before conversion; use its own float.h spelling.
                        if code=='M' and abs(number)==3.4028234663852886e38:
                            literal=('-' if number<0 else '')+'3.402823466e+38'
                        if not any(c in literal for c in '.eE'):literal+='.0'
                        if code=='M':literal+='f'
                    elif code=='I':literal=str(number)+'u'
                    elif number==-2147483648:literal='(-2147483647 - 1)'
                    else:literal=str(number)
                    bytes_field(cursor,at)
                    ctype={'M':'float','N':'double','H':'int','I':'unsigned int'}[code]
                    members.append('  '+ctype+' s%08x;'%at)
                    if not bss:values.append('  '+literal)
                    typed_records.append(dict(address=address,type=ctype,names=sorted(names)))
                    cursor=at+size
                bytes_field(cursor,stop)
            for off,ti,kind in rels:
                if not pos<=off<end:continue
                if kind!=6:raise ValueError('data relocation is not DIR32')
                opaque(cursor,off)
                target=c.symbols[ti]['name']
                if not re.fullmatch(r'_[A-Za-z_][A-Za-z_0-9]*',target):
                    raise ValueError('C identifier mapping required: '+target)
                name=target[1:]; declarations.add(name)
                addend=struct.unpack_from('<I',raw,off)[0]
                members.append('  const unsigned char *p%08x;'%off)
                values.append('  '+name+(' + %du'%addend if addend else ''))
                part_rels.append(dict(offset=off-pos,target=target,addend=addend))
                cursor=off+4
            opaque(cursor,end)
            # 16-byte starts preserve all original SSE alignment residues.
            # End lengths need no compiler-invented struct tail padding.
            lines=['// LOCAL GAME-DERIVED BUILD PRODUCT. DO NOT COMMIT OR DISTRIBUTE.',
                   '// Packed scalar types follow unambiguous recipe decorations; other layouts are opaque.',
                   '#pragma pack(push,1)']
            lines += ['extern "C" unsigned char '+name+'[];' for name in sorted(declarations)]
            lines += ['struct '+anchor+'_type {']+members+['};','#pragma pack(pop)',
                      'typedef char '+anchor+'_size_check[(sizeof('+anchor+'_type)==%d)?1:-1];'%(end-pos)]
            writable=bool(sec['flags']&0x80000000)
            section=sec['name'] if not bss else '.bss'
            # A single named section per class retains explicit input object order.
            if section not in ('.bss','.tls'):
                lines += ['#pragma section("'+section+'",read'+(',write' if writable else '')+')']
            attr='__declspec(thread) ' if section=='.tls' else ('' if bss else '__declspec(allocate("'+section+'")) ')
            lines += ['extern "C" {',attr+'__declspec(align(16)) '+anchor+'_type '+anchor+
                      (';' if bss else ' = {\n'+',\n'.join(values)+'\n};'),'}','']
            path=root/(anchor+'.cpp');path.write_bytes('\r\n'.join(lines).encode('ascii'))
            labels=[dict(name=t['name'],offset=t['value']-pos) for t in symbols
                    if t['section']==sn and pos<=t['value']<end]
            records.append(dict(index=index,source=str(path),anchor='_'+anchor,
                                section=section,original_section=sn,offset=pos,size=end-pos,bss=bss,
                                original_address=origin+pos,source_sha256=digest(path),
                                labels=labels,relocations=part_rels,
                                opaque_bytes=end-pos-4*len(part_rels)))
            pos=end
    absolute=[dict(name=t['name'],value=t['value']) for t in symbols if t['section']==-1]
    directives=[c.data[s['raw']:s['raw']+s['size']].decode('ascii') for s in c.sections[1:] if s['name']=='.drectve']
    manifest=dict(format=1,input=str(a.input),input_sha256=digest(a.input),
                  contains_game_bytes=True,compiler_reads_original_exe=False,
                  type_policy='unambiguous recipe scalar decorations; symbolic pointers; other bytes opaque',
                  typed_fields=typed_records,
                  records=records,absolute_symbols=absolute,directives=directives,
                  counts=dict(initialized_bytes=sum(r['size'] for r in records if not r['bss']),
                              zero_fill_bytes=sum(r['size'] for r in records if r['bss']),
                              symbolic_pointers=sum(len(r['relocations']) for r in records),
                              chunks=len(records),typed_scalar_fields=len(typed_records)))
    dump(root/'data_manifest.json',manifest);print(json.dumps(manifest['counts'],indent=2))


def compile_sources(a):
    from phase2_policy import CoffView
    from standalone_common import append_symbols, COFF, dump, reserve
    import placelink
    manifest=json.loads((a.out/'data_manifest.json').read_text());objects=[];proofs=[]
    if digest(a.input)!=manifest['input_sha256']:raise ValueError('exported storage oracle changed; re-export explicitly')
    # Identical compiler environment to the normal build wrapper, no game paths.
    from config import compiler_environment
    env=compiler_environment()
    env['INCLUDE']=';'.join(str(a.toolchain/p) for p in ('VC/include','SDK/Include'))
    target=a.out/'objects';target.mkdir(exist_ok=True)
    for r in manifest['records']:
        source=Path(r['source']);obj=target/(source.stem+'.obj');raw=target/(source.stem+'.compiler.obj')
        if digest(source)!=r['source_sha256']:raise ValueError('source changed since manifest')
        proof_path=target/(source.stem+'.proof.json')
        if obj.exists() and proof_path.exists():
            old=json.loads(proof_path.read_text())
            if old['source_sha256']==r['source_sha256'] and old['object_sha256']==digest(obj):
                proofs.append(old);objects.append(str(obj));continue
        reserve(extra=64*1024**2,timeout=3)
        import psutil
        if placelink.compiler_count()>=8:
            raise RuntimeError('eight compiler processes already running; rerun to resume')
        from config import ROOT
        command=[sys.executable, '-B',str(ROOT/'tools/msvc.py'),'/nologo','/c','/TP','/Zl','/Od','/GS-',
                 '/Fo'+str(raw),str(source)]
        with (target/(source.stem+'.log')).open('w') as log:
            process=subprocess.Popen(command,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                     creationflags=0x08000000 if os.name=='nt' else 0)
            minimum_free=psutil.virtual_memory().available
            while process.poll() is None:
                minimum_free=min(minimum_free,psutil.virtual_memory().available)
                if minimum_free<placelink.RESERVE:
                    process.kill();process.wait()
                    raise RuntimeError('compiler stopped to preserve 3 GiB free RAM; rerun to resume')
                time.sleep(.05)
        if process.returncode:raise RuntimeError('C++ compile failed: '+str(source))
        c=CoffView(raw);anchors=[t for t in c.symbols.values() if t['name']==r['anchor'] and t['section']>0]
        if len(anchors)!=1:raise ValueError('missing or ambiguous compiled anchor')
        t=anchors[0];s=c.sections[t['section']];off=t['value']
        if off+r['size']>s['size']:raise ValueError('compiler layout too short')
        compiled=c.data[s['raw']+off:s['raw']+off+r['size']] if s['raw'] else b''
        expected_rels=sorted((v['offset'],v['target'],v['addend']) for v in r['relocations'])
        actual_rels=sorted((x-off,c.symbols[ti]['name'],struct.unpack_from('<I',compiled,x-off)[0])
                           for x,ti,k in s['relocs'] if off<=x<off+r['size'] and k==6)
        if actual_rels!=expected_rels:raise ValueError('compiler relocation fields differ')
        # Compare to the exported object only as a validation oracle. Compilation
        # itself needs solely the local .cpp; the original EXE is never reopened.
        baseline=CoffView(a.input);bs=baseline.sections[r['original_section']]
        expected=baseline.data[bs['raw']+r['offset']:bs['raw']+r['offset']+r['size']] if bs['raw'] else b''
        if compiled!=expected:raise ValueError('compiler initialized bytes differ')
        labels=[(v['name'],t['section'],off+v['offset']) for v in r['labels']]
        append_symbols(raw,obj,labels)
        proof=dict(source_sha256=r['source_sha256'],object_sha256=digest(obj),
                   source=str(source),object=str(obj),initialized_bytes_equal=True,
                   relocations_equal=True,labels_added=len(labels),size=r['size'],
                   minimum_free_memory_bytes=minimum_free)
        dump(proof_path,proof);proofs.append(proof);objects.append(str(obj))
        print(source.stem,r['size'],'bytes checked',flush=True)
    c=COFF()
    for t in manifest['absolute_symbols']:c.symbol(t['name'],-1,t['value'])
    for d in manifest['directives']:c.section('.drectve',d.encode('ascii'),0x100a00)
    c.write(target/'data_labels.obj');objects.append(str(target/'data_labels.obj'))
    dump(a.out/'data_objects.json',objects)
    dump(a.out/'data_compile_audit.json',dict(passed=True,counts=manifest['counts'],proofs=proofs,
                                            max_compiler_processes=1,original_exe_read=False))
