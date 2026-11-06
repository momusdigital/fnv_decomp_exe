"""Extract local PE resources to a standard .res file; never commit the output."""
import struct


def align4(data):
    return data + bytes((-len(data)) & 3)


def resource_record(kind,name,language,payload):
    encode=lambda value:struct.pack('<HH',0xffff,value) if isinstance(value,int) else value.encode('utf-16-le')+b'\0\0'
    names=align4(encode(kind)+encode(name))
    header=struct.pack('<II',len(payload),8+len(names)+16)+names+struct.pack('<IHHII',0,0x1030,language,0,0)
    return header+align4(payload)


def resource_tree(pe):
    start,size=pe.directory(2);leaves=[];directories={}
    if not start:return leaves,directories
    def name(raw):
        if not raw & 0x80000000:return raw
        off=raw & 0x7fffffff;n=struct.unpack('<H',pe.read(start+off,2))[0]
        return pe.read(start+off+2,2*n).decode('utf-16-le')
    def walk(off,path):
        if off+16>size or len(path)>3:raise ValueError('invalid resource tree')
        directories[tuple(path)]=struct.unpack('<IIHH',pe.read(start+off,12))
        n1,n2=struct.unpack('<HH',pe.read(start+off+12,4))
        for i in range(n1+n2):
            key,value=struct.unpack('<II',pe.read(start+off+16+8*i,8));keys=path+[name(key)]
            if value & 0x80000000:walk(value & 0x7fffffff,keys)
            else:
                if len(keys)!=3:raise ValueError('resource depth must be type/name/language')
                rva,n,cp,reserved=struct.unpack('<IIII',pe.read(start+value,16))
                if value+16>size:raise ValueError('invalid resource data entry')
                leaves.append((keys,pe.read(pe.base+rva,n),cp,reserved))
    walk(0,[])
    if len({tuple(row[0]) for row in leaves})!=len(leaves):raise ValueError('duplicate resource identity')
    return leaves,directories


def extract(pe):
    return [(keys,payload) for keys,payload,_,_ in resource_tree(pe)[0]]


def resource_object(pe,coff_type):
    """.res has no CodePage field. Emit resource COFF to retain PE metadata too."""
    leaves,directories=resource_tree(pe)
    tree={}
    for keys,payload,cp,reserved in leaves:
        node=tree
        for key in keys[:-1]:node=node.setdefault(key,{})
        node[keys[-1]]=(payload,cp,reserved)
    headers=bytearray();payloads=bytearray();relocations=[]
    def walk(node,path):
        offset=len(headers);keys=sorted(node,key=lambda k:(not isinstance(k,str),k))
        headers.extend(struct.pack('<IIHHHH',*directories[tuple(path)],sum(isinstance(k,str) for k in keys),sum(isinstance(k,int) for k in keys)))
        headers.extend(bytes(8*len(keys)))
        for i,key in enumerate(keys):
            if isinstance(key,str):
                raw=key.encode('utf-16-le');name=0x80000000|len(headers)
                headers.extend(struct.pack('<H',len(raw)//2)+raw)
                headers.extend(bytes((-len(headers))&3))
            else:name=key
            value=node[key]
            if isinstance(value,dict):target=0x80000000|walk(value,path+[key])
            else:
                payload,cp,reserved=value;target=len(headers)
                headers.extend(struct.pack('<IIII',len(payloads),len(payload),cp,reserved))
                relocations.append((target,len(payloads)))
                payloads.extend(align4(payload))
            struct.pack_into('<II',headers,offset+16+8*i,name,target)
        return offset
    walk(tree,[])
    c=coff_type();sn=c.section('.rsrc$01',headers,0x40300040)
    data=c.section('.rsrc$02',payloads,0x40300040)
    c.symbol('_deexe_resource_payload',data)
    for off,addend in relocations:c.reloc(sn,off,'_deexe_resource_payload',7,addend)
    return c


def resource_audit(original,actual):
    import hashlib
    old,od=resource_tree(original);new,nd=resource_tree(actual)
    old={tuple(k):(p,cp,r) for k,p,cp,r in old};new={tuple(k):(p,cp,r) for k,p,cp,r in new}
    rows=[]
    for key in sorted(old.keys()|new.keys(),key=repr):
        a=old.get(key);b=new.get(key)
        rows.append(dict(identity=list(key),equal=a==b,original_codepage=a[1] if a else None,
                         linked_codepage=b[1] if b else None,
                         original_sha256=hashlib.sha256(a[0]).hexdigest() if a else None,
                         linked_sha256=hashlib.sha256(b[0]).hexdigest() if b else None))
    return dict(passed=old==new and od==nd,original_leaves=len(old),linked_leaves=len(new),
                payload_bytes=sum(len(v[0]) for v in old.values()),leaves=rows,
                directory_metadata_equal=od==nd)
