"""Independent storage, pointer and TLS checks on the native linked image."""
import re
import struct


def map_symbols(path):
    result={}
    for line in path.read_text(errors='replace').splitlines():
        m=re.match(r'\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8})\b',line)
        if m:result[m[1]]=int(m[2],16)
    return result


def storage_audit(manifest, baseline, actual, symbols):
    from phase2_policy import CoffView
    c=CoffView(baseline);errors=[];checked=0;pointers=0;labels=0
    for r in manifest['records']:
        placed=symbols.get(r['anchor'])
        if placed is None:
            errors.append(dict(source=r['source'],error='missing compiler anchor'));continue
        if placed%16!=r['original_address']%16:
            errors.append(dict(source=r['source'],error='storage alignment residue changed',
                               original=r['original_address'],linked=placed))
        sec=c.sections[r['original_section']]
        raw=bytearray(c.data[sec['raw']+r['offset']:sec['raw']+r['offset']+r['size']]) if sec['raw'] else bytearray(r['size'])
        for v in r['relocations']:
            target=symbols.get(v['target'])
            if target is None:
                errors.append(dict(error='missing pointer target',target=v['target']));continue
            struct.pack_into('<I',raw,v['offset'],(target+v['addend'])&0xffffffff);pointers+=1
        found=actual.read(placed,r['size']);checked+=r['size']
        if found!=raw:
            bad=[i for i,(x,y) in enumerate(zip(found,raw)) if x!=y]
            errors.append(dict(error='storage bytes differ',original=r['original_address'],linked=placed,
                               mismatched_bytes=len(bad),first_offsets=bad[:20]))
        for t in r['labels']:
            labels+=1
            if symbols.get(t['name'])!=placed+t['offset']:
                errors.append(dict(error='interior label misplaced',symbol=t['name']))
    return dict(passed=not errors,storage_bytes_checked=checked,symbolic_pointers_checked=pointers,
                labels_checked=labels,unplaced_storage_bytes=0 if not errors else None,errors=errors)




def storage_highlow_audit(manifest,original,actual,symbols):
    """Direct manifest anchors cover fields lost by coarse COFF placement scans."""
    highlow=dict(original.relocations());errors=[];checked=0
    for record in manifest['records']:
        anchor=symbols[record['anchor']]
        for rel in record['relocations']:
            name=rel['target']
            if not re.fullmatch('_fnv_va_[0-9a-f]{8}',name):
                errors.append(dict(error='unproved original storage target',symbol=name));continue
            original_target=(int(name[-8:],16)+rel['addend'])&0xffffffff
            site=record['original_address']+rel['offset']
            expected=(symbols[name]+rel['addend'])&0xffffffff
            linked=anchor+rel['offset'];value=struct.unpack('<I',actual.read(linked,4))[0]
            checked+=1
            if highlow.get(site)!=original_target or value!=expected:
                errors.append(dict(error='storage HIGHLOW identity differs',original_site=site,linked_site=linked))
    return dict(passed=not errors,checked=checked,unplaced_sites_skipped=0,errors=errors)


def tls_audit(original,actual):
    old,_=original.directory(9);new,_=actual.directory(9)
    if not old:return dict(passed=not new,original_tls_present=False)
    if not new:return dict(passed=False,error='TLS directory absent')
    ostart,oend,oi,oc,oz,och=struct.unpack('<IIIIII',original.read(old,24))
    start,end,index,callbacks,zero,chars=struct.unpack('<IIIIII',actual.read(new,24))
    # This image's TLS template contains no HIGHLOW pointers; templates with
    # pointers must use the full storage audit's symbolic comparison instead.
    plain=not any(ostart<=site<oend for site,_ in original.relocations())
    if not plain:return dict(passed=False,error='TLS template requires symbolic pointer comparison')
    callback_values=[]
    if callbacks:
        for i in range(65536):
            value=struct.unpack('<I',actual.read(callbacks+i*4,4))[0]
            if not value:break
            callback_values.append(value)
        else:return dict(passed=False,error='TLS callback list unterminated')
    original_callbacks=[]
    if oc:
        for i in range(65536):
            value=struct.unpack('<I',original.read(oc+i*4,4))[0]
            if not value:break
            original_callbacks.append(value)
    result=dict(template_bytes=end-start,template_bytes_equal=end-start==oend-ostart and actual.read(start,end-start)==original.read(ostart,oend-ostart),
                template_starts_at_section_base=bool(actual.section(start) and actual.section(start)['lo']==start),
                index_mapped=bool(actual.section(index)),zero_fill=zero,callbacks_empty=not callback_values,
                characteristics_equal=chars==och)
    result['passed']=bool(result['template_bytes_equal'] and result['template_starts_at_section_base'] and result['index_mapped']
                          and zero==oz and not original_callbacks and not callback_values and chars==och)
    return result
