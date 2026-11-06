"""Complete PE32 header inventory; distinguish loader contract from new layout.

Relinking changes addresses, sizes, timestamps, debug records and section layout.
These differences are enumerated, never confused with equal loader policy.
"""
import struct


COFF_FIELDS=list(zip(('Machine','NumberOfSections','TimeDateStamp','PointerToSymbolTable',
                      'NumberOfSymbols','SizeOfOptionalHeader','Characteristics'),
                     (0,2,4,8,12,16,18),('H','H','I','I','I','H','H')))
OPTIONAL_FIELDS=[('Magic',0,'H'),('MajorLinkerVersion',2,'B'),('MinorLinkerVersion',3,'B')]
OPTIONAL_FIELDS+=list(zip(('SizeOfCode','SizeOfInitializedData','SizeOfUninitializedData',
                          'AddressOfEntryPoint','BaseOfCode','BaseOfData','ImageBase',
                          'SectionAlignment','FileAlignment'),range(4,40,4),['I']*9))
OPTIONAL_FIELDS+=list(zip(('MajorOperatingSystemVersion','MinorOperatingSystemVersion',
                          'MajorImageVersion','MinorImageVersion','MajorSubsystemVersion',
                          'MinorSubsystemVersion'),range(40,52,2),['H']*6))
OPTIONAL_FIELDS+=list(zip(('Win32VersionValue','SizeOfImage','SizeOfHeaders','CheckSum'),range(52,68,4),['I']*4))
OPTIONAL_FIELDS+=[('Subsystem',68,'H'),('DllCharacteristics',70,'H')]
OPTIONAL_FIELDS+=list(zip(('SizeOfStackReserve','SizeOfStackCommit','SizeOfHeapReserve',
                          'SizeOfHeapCommit','LoaderFlags','NumberOfRvaAndSizes'),range(72,96,4),['I']*6))
STRUCTURAL={
    'NumberOfSections':'new native section layout',
    'TimeDateStamp':'native build time',
    'SizeOfCode':'native code layout; independent code audit',
    'SizeOfInitializedData':'native data layout; independent storage audit',
    'SizeOfUninitializedData':'native zero-fill layout; independent storage audit',
    'AddressOfEntryPoint':'adapted CRT entry; independent entry-symbol audit',
    'BaseOfCode':'native section layout',
    'BaseOfData':'native section layout',
    'SizeOfImage':'native section layout',
    'SizeOfHeaders':'native section count and omitted DOS stub',
    'CheckSum':'native image checksum; original checksum is not reusable',
}


def inventory(data):
    nt=struct.unpack_from('<I',data,60)[0];opt=nt+24
    if data[:2]!=b'MZ' or data[nt:nt+4]!=b'PE\0\0':raise ValueError('invalid PE signature')
    fields={name:struct.unpack_from('<'+fmt,data,nt+4+off)[0] for name,off,fmt in COFF_FIELDS}
    fields.update({name:struct.unpack_from('<'+fmt,data,opt+off)[0] for name,off,fmt in OPTIONAL_FIELDS})
    if fields['Magic']!=0x10b or fields['SizeOfOptionalHeader']!=224 or fields['NumberOfRvaAndSizes']!=16:
        raise ValueError('expected complete PE32 header with 16 directories')
    directories=[list(struct.unpack_from('<II',data,opt+96+i*8)) for i in range(16)]
    sections=[];start=opt+fields['SizeOfOptionalHeader']
    for i in range(fields['NumberOfSections']):
        values=struct.unpack_from('<8sIIIIIIHHI',data,start+40*i)
        sections.append(dict(zip(('Name','VirtualSize','VirtualAddress','SizeOfRawData',
                                  'PointerToRawData','PointerToRelocations','PointerToLinenumbers',
                                  'NumberOfRelocations','NumberOfLinenumbers','Characteristics'),
                                 (values[0].rstrip(b'\0').decode('ascii'),*values[1:]))))
    # Includes every DOS field, reserved word and the omitted DOS stub verbatim
    # in this private evidence file. No header bytes are silently discarded.
    return dict(fields=fields,dos_header_and_stub_hex=data[:nt].hex(),
                directories=directories,sections=sections)


def audit(original,actual):
    old=inventory(original.data);new=inventory(actual.data);rows=[];errors=[]
    for name,value in old['fields'].items():
        found=new['fields'][name];policy=STRUCTURAL.get(name,'must equal original')
        rows.append(dict(field=name,original=value,linked=found,equal=value==found,policy=policy))
        if value!=found and name not in STRUCTURAL:errors.append(name)
    directory_fields=[]
    for index,(a,b) in enumerate(zip(old['directories'],new['directories'])):
        if index in (1,2,5,9,12):policy='native placement; independent content audit'
        elif index in (4,6):
            policy='original certificate/debug record intentionally omitted from native image'
            if b!=[0,0]:errors.append('native certificate/debug directory must be absent: '+str(index))
        else:
            policy='must equal original'
            if a!=b:errors.append('data directory '+str(index))
        for field,pos in [('VirtualAddress',0),('Size',1)]:
            directory_fields.append(dict(directory=index,field=field,original=a[pos],linked=b[pos],
                                         equal=a[pos]==b[pos],policy=policy))
    for section in new['sections']:
        if section['Characteristics']&0xa0000000==0xa0000000:
            errors.append('writable executable section: '+section['Name'])
    before={s['Name']:s for s in old['sections']};after={s['Name']:s for s in new['sections']}
    section_fields=[]
    for name in sorted(before.keys()|after.keys()):
        a=before.get(name,{});b=after.get(name,{})
        for field in sorted(a.keys()|b.keys()):
            section_fields.append(dict(section=name,field=field,original=a.get(field),linked=b.get(field),
                                       equal=a.get(field)==b.get(field),policy='native section layout; independent storage/code audits'))
    return dict(passed=not errors,errors=errors,fields=rows,directory_fields=directory_fields,section_fields=section_fields,original=old,linked=new,
                dos_policy='native LINK DOS header/stub replaces copied game stub',
                directory_policy='all 16 address/size pairs enumerated; native addresses are checked by separate resource/TLS/import/HIGHLOW audits',
                section_policy='every field enumerated; native layout changes; no writable executable sections')


def linker_options(pe):
    """Make inherited loader policy explicit instead of depending on LINK defaults."""
    f=inventory(pe.data)['fields']
    if f['Machine']!=0x14c or f['Subsystem']!=2:raise ValueError('expected i386 Windows GUI image')
    dll=f['DllCharacteristics']
    if dll & ~0x8140:raise ValueError('unhandled original DLL characteristics')
    return ['/MANIFEST:NO','/SUBSYSTEM:WINDOWS,%d.%02d'%(f['MajorSubsystemVersion'],f['MinorSubsystemVersion']),
            '/OSVERSION:%d.%d'%(f['MajorOperatingSystemVersion'],f['MinorOperatingSystemVersion']),
            '/VERSION:%d.%d'%(f['MajorImageVersion'],f['MinorImageVersion']),
            '/LARGEADDRESSAWARE'+('' if f['Characteristics']&0x20 else ':NO'),
            '/DYNAMICBASE'+('' if dll&0x40 else ':NO'),'/NXCOMPAT'+('' if dll&0x100 else ':NO'),
            '/TSAWARE'+('' if dll&0x8000 else ':NO'),
            '/STACK:%d,%d'%(f['SizeOfStackReserve'],f['SizeOfStackCommit']),
            '/HEAP:%d,%d'%(f['SizeOfHeapReserve'],f['SizeOfHeapCommit'])]
