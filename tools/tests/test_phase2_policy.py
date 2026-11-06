"""Synthetic Phase 2 policy checks; no game bytes in test fixtures."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'decomp'/'tools'))
import placelink as place
from standalone_common import COFF,database,label
from phase2_policy import CoffView,discard_unreachable,ownership,reconcile_comdats,canonical_code_references
from standalone import rewrite_objects,tool
from gen_aliases import generate,weak_aliases


def comdat(path,name,body,missing=None):
    c=COFF();sn=c.section('.text',body,0x60501020)
    section_symbol=c.symbol('.text',sn,0,storage=3)
    c.symbol(name,sn,0)
    if missing:c.reloc(sn,1,missing,20)
    c.write(path)
    d=bytearray(path.read_bytes());ptr,n=struct.unpack_from('<II',d,8)
    d[ptr+section_symbol*18+17]=1
    rr=struct.unpack_from('<I',d,44)[0]
    for j,(off,ti,kind) in enumerate(c.sections[0]['relocs']):
        if ti>section_symbol:struct.pack_into('<I',d,rr+j*10+4,ti+1)
    aux=bytearray(18);struct.pack_into('<IHH',aux,0,len(body),int(bool(missing)),0);aux[14]=1
    struct.pack_into('<I',d,12,n+1)
    cut=ptr+(section_symbol+1)*18
    path.write_bytes(d[:cut]+aux+d[cut:])


class PolicyTests(unittest.TestCase):
    def test_index_proves_defined_code_and_runtime_targets(self):
        from standalone import setup,index_objects
        with tempfile.TemporaryDirectory(prefix='policy_proof_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            c=COFF();sn=c.section('.text',b'\xe8'+bytes(4)+b'\xe8'+bytes(4)+b'\xc3',0x60500020)
            c.symbol('_entry',sn);c.reloc(sn,1,'_memcpy',20);c.reloc(sn,6,'_defined_copy',20)
            sn=c.section('.text',b'\xc3',0x60500020);c.symbol('_defined_copy',sn);c.write(p/'proof.obj')
            original=b'\xe8'+struct.pack('<i',0x402000-0x401005)+b'\xe8'+struct.pack('<i',0x403000-0x40100a)+b'\xc3'
            class Original:
                base=0x400000
                def relocations(self):return []
                def read(self,a,n):return original[a-0x401000:a-0x401000+n]
            units=[dict(source='synthetic.cpp',functions=[dict(symbol='_entry',address='0x00401000',size=11)])]
            setup(db,units);index_objects(db,units,[p/'proof.obj'],Original(),p)
            self.assertEqual(db.execute('SELECT address FROM binding WHERE name=?',('_memcpy',)).fetchone()[0],0x402000)
            self.assertEqual(db.execute('SELECT address FROM binding WHERE name=?',('_defined_copy',)).fetchone()[0],0x403000)
            db.close()

    def test_binding_collapse_requires_complete_identical_bodies(self):
        from binding_policy import reconcile_bindings
        with tempfile.TemporaryDirectory(prefix='policy_equivalence_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            for name,aa in [('_identical',[0x401000,0x402000]),('_different',[0x401000,0x403000])]:
                for a in aa:db.execute('INSERT INTO binding VALUES (?,?,?)',(name,a,0))
            for a in [0x401000,0x402000,0x403000]:
                db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(a,a+1,0,1,0,'_body','function'))
            class Original:
                def relocations(self):return []
                def read(self,a,n):return b'\xcc' if a==0x403000 else b'\xc3'
            result=reconcile_bindings(db,[],Original(),p)
            self.assertEqual(result,dict(collapsed=1,remaining=1))
            self.assertEqual(db.execute('SELECT COUNT(DISTINCT address) FROM binding WHERE name=?',('_identical',)).fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(DISTINCT address) FROM binding WHERE name=?',('_different',)).fetchone()[0],2)
            db.close()

    def test_exact_matched_operands_resolve_conflicting_standins(self):
        with tempfile.TemporaryDirectory(prefix='policy_exact_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE matched_reference(name TEXT,unit INTEGER)')
            paths=[];original={}
            for unit,a,target in [(0,0x401000,0x402000),(1,0x403000,0x404000)]:
                path=p/('unit%d.obj'%unit);paths.append(path)
                c=COFF();sn=c.section('.text',b'\xe8'+bytes(4)+b'\xc3',0x60500020)
                c.symbol('_entry%d'%unit,sn);c.reloc(sn,1,'_collision',20);c.write(path)
                db.execute('INSERT INTO matched_reference VALUES (?,?)',('_collision',unit))
                db.execute('INSERT INTO binding VALUES (?,?,?)',('_collision',target,unit))
                db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(a,a+6,unit,1,0,'_entry%d'%unit,'function'))
                original[a+1]=struct.pack('<i',target-a-5)
            class Original:
                base=0x400000
                def read(self,a,n):return original[a]
                def relocations(self):return [(0x401001,0x405000)]
                def section(self,a):return dict(name='.text')
            counts=canonical_code_references(db,paths,Original(),p)
            self.assertEqual(counts['exact_matched_operands'],2)
            for path,target in zip(paths,[0x402000,0x404000]):
                c=CoffView(path);ti=c.sections[1]['relocs'][0][1]
                self.assertEqual(c.symbols[ti]['name'],label(target))
            db.close()

    def test_address_shaped_literal_does_not_relocate(self):
        with tempfile.TemporaryDirectory(prefix='policy_literal_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE matched_reference(name TEXT,unit INTEGER)')
            c=COFF();sn=c.section('.text',b'\x25'+bytes(4)+b'\xb8'+bytes(4)+b'\xc3',0x60500020)
            c.symbol('_entry',sn);c.reloc(sn,1,'_mask',6,7);c.reloc(sn,6,'_pointer',6)
            c.write(p/'entry.obj')
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x40100b,0,1,0,'_entry','function'))
            class Original:
                base=0x400000
                def relocations(self):return [(0x401006,0x00ffffff)]
                def read(self,a,n):return struct.pack('<I',0x00ffffff)
                def section(self,a):return dict(name='.rdata')
            result=canonical_code_references(db,[p/'entry.obj'],Original(),p)
            c=CoffView(p/'entry.obj');sec=c.sections[1]
            self.assertEqual(result['literal_relocations_removed'],1)
            self.assertEqual(struct.unpack_from('<I',c.data,sec['raw']+1)[0],0x00ffffff)
            self.assertEqual([(off,kind) for off,ti,kind in sec['relocs']],[(6,6)])
            self.assertEqual(c.symbols[sec['relocs'][0][1]]['name'],label(0x00ffffff))
            db.close()

    def test_private_eh_reference_uses_original_generated_handler(self):
        with tempfile.TemporaryDirectory(prefix='policy_private_eh_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE matched_reference(name TEXT,unit INTEGER)')
            c=COFF();sn=c.section('.text',b'\xb8'+bytes(4)+b'\xc3',0x60500020)
            c.symbol('_entry',sn)
            eh=c.section('.text$x',b'\xc3',0x60500020);c.symbol('private_handler',eh,storage=3)
            c.reloc(sn,1,'private_handler',6);c.write(p/'entry.obj')
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x401006,0,1,0,'_entry','function'))
            class Original:
                base=0x400000
                def read(self,a,n):return struct.pack('<I',0x405000)
                def relocations(self):return [(0x401001,0x405000)]
                def section(self,a):return dict(name='.text')
            canonical_code_references(db,[p/'entry.obj'],Original(),p)
            c=CoffView(p/'entry.obj');ti=c.sections[1]['relocs'][0][1]
            self.assertEqual(c.symbols[ti]['name'],label(0x405000))
            db.close()


    def test_unreferenced_associative_eh_copy_is_discarded(self):
        with tempfile.TemporaryDirectory(prefix='policy_eh_association_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            c=COFF();sn=c.section('.text',b'\xc3',0x60500020);c.symbol(label(0x401000),sn)
            eh=c.section('.text$x',b'\xe8'+bytes(4)+b'\xc3',0x60501020)
            sx=c.symbol('.text$x',eh,storage=3);c.reloc(eh,1,'_unmatched_cleanup',20);c.write(p/'entry.obj')
            raw=bytearray((p/'entry.obj').read_bytes());ptr,n=struct.unpack_from('<II',raw,8)
            raw[ptr+sx*18+17]=1
            for sn in range(2):
                rp=struct.unpack_from('<I',raw,20+sn*40+24)[0]
                for j,(_,ti,_) in enumerate(c.sections[sn]['relocs']):
                    if ti>sx:struct.pack_into('<I',raw,rp+j*10+4,ti+1)
            aux=bytearray(18);struct.pack_into('<IHH',aux,0,6,1,0);aux[14]=5;struct.pack_into('<h',aux,12,1)
            struct.pack_into('<I',raw,12,n+1);cut=ptr+(sx+1)*18
            (p/'entry.obj').write_bytes(raw[:cut]+aux+raw[cut:])
            c=COFF();sn=c.section('.rdata',bytes(4));c.reloc(sn,0,label(0x401000),6);c.write(p/'image_data.obj')
            (p/'image_report.json').write_text(json.dumps(dict(tls_callbacks=[])))
            class Original:
                entry=0x401000
                def directory(self,n):return (0,0)
            discard_unreachable(db,[p/'entry.obj'],Original(),p)
            self.assertTrue(CoffView(p/'entry.obj').sections[2]['flags']&0x800)
            self.assertFalse(db.execute('SELECT 1 FROM live_name WHERE name=?',('_unmatched_cleanup',)).fetchone())
            db.close()

    def test_secrel_operand_names_effective_tls_field(self):
        with tempfile.TemporaryDirectory(prefix='policy_tls_field_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE matched_reference(name TEXT,unit INTEGER)')
            c=COFF();sn=c.section('.text',b'\xb8'+bytes(4)+b'\xc3',0x60500020);c.symbol('_entry',sn)
            c.reloc(sn,1,'_view_before_tls',11,8);c.write(p/'entry.obj')
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x401006,0,1,0,'_entry','function'))
            class Original:
                base=0x400000
                sections=[dict(name='.tls',lo=0x500000)]
                def relocations(self):return []
                def read(self,a,n):return bytes(4)
                def section(self,a):return dict(name='.tls')
            canonical_code_references(db,[p/'entry.obj'],Original(),p)
            c=CoffView(p/'entry.obj');ti=c.sections[1]['relocs'][0][1]
            self.assertEqual(c.symbols[ti]['name'],label(0x500000))
            self.assertEqual(c.data[c.sections[1]['raw']+1:c.sections[1]['raw']+5],bytes(4))
            db.close()

    def test_mixed_eh_contribution_keeps_only_proved_islands(self):
        from phase2_policy import trim_unmatched_eh
        with tempfile.TemporaryDirectory(prefix='policy_eh_island_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE live_name(name TEXT PRIMARY KEY)')
            c=COFF();sn=c.section('.text$x',b'\xe8'+bytes(4)+b'\xc3\xc3',0x60500020)
            c.symbol(label(0x405000),sn,6);c.reloc(sn,1,'_unproved_cleanup',20);c.write(p/'entry.obj')
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x405000,0x405001,0,1,6,'<EH>','eh'))
            result=trim_unmatched_eh(db,[p/'entry.obj'],p)
            c=CoffView(p/'entry.obj')
            self.assertEqual(result['relocations_removed'],1)
            self.assertEqual(c.sections[1]['relocs'],[])
            self.assertEqual(c.data[c.sections[1]['raw']+6],0xc3)
            db.close()

    def test_eh_hole_is_not_trimmed_when_a_branch_enters_it(self):
        from phase2_policy import trim_unmatched_eh
        with tempfile.TemporaryDirectory(prefix='policy_eh_hole_reject_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE live_name(name TEXT PRIMARY KEY)')
            c=COFF();sn=c.section('.text$x',b'\xeb\x02'+b'\xcc'*4+b'\xc3',0x60500020)
            c.symbol(label(0x405000),sn);c.write(p/'entry.obj');before=(p/'entry.obj').read_bytes()
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x405000,0x405002,0,1,0,'<EH>','eh'))
            with self.assertRaisesRegex(ValueError,'branch enters'):
                trim_unmatched_eh(db,[p/'entry.obj'],p)
            self.assertEqual((p/'entry.obj').read_bytes(),before)
            db.close()

    def test_external_tls_effective_fields_are_discovered_before_generation(self):
        from standalone import canonical_tls
        with tempfile.TemporaryDirectory(prefix='policy_tls_discovery_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            c=COFF();sn=c.section('.text',b'\xb8'+bytes(4)+b'\xc3',0x60500020);c.symbol('_entry',sn)
            c.reloc(sn,1,'_external_tls_view',11,8);c.write(p/'entry.obj')
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x401006,0,1,0,'_entry','function'))
            class Original:
                sections=[dict(name='.tls',lo=0x500000,hi=0x500100)]
                def read(self,a,n):return struct.pack('<I',0x20)
            canonical_tls(db,[p/'entry.obj'],Original(),p)
            self.assertEqual(db.execute('SELECT reason FROM address WHERE address=0x500020').fetchone()[0],'tls_effective_field')
            db.close()

    def test_native_iat_name_cannot_alias_another_import(self):
        with tempfile.TemporaryDirectory(prefix='policy_iat_identity_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE matched_reference(name TEXT,unit INTEGER)')
            public='__imp__GetCurrentProcessId@0';other='__imp__GetCurrentThreadId@0'
            db.execute('INSERT INTO reference VALUES (?,?)',(public,0))
            db.execute('INSERT INTO matched_reference VALUES (?,?)',(public,0))
            db.execute('INSERT INTO binding VALUES (?,?,?)',(public,0x500004,0))
            db.execute('INSERT INTO import VALUES (?,?,?,?)',(0x500000,'kernel32.dll','GetCurrentProcessId',public))
            db.execute('INSERT INTO import VALUES (?,?,?,?)',(0x500004,'kernel32.dll','GetCurrentThreadId',other))
            generate(db,p)
            self.assertEqual(db.execute('SELECT target,status FROM alias WHERE name=?',(public,)).fetchone(),(public,'ok_import'))
            self.assertFalse(CoffView(p/'aliases.obj').symbols)
            db.close()


    def test_compiler_alternatename_keeps_fallback_and_matching_include_is_dropped(self):
        with tempfile.TemporaryDirectory(prefix='policy_directives_') as folder:
            p=Path(folder);db=database(p/'state.sqlite');comdat(p/'impl.obj','_implementation',b'\xc3')
            c=COFF();sn=c.section('.text',b'\xe8\0\0\0\0\xc3',0x60500020)
            c.symbol(label(0x401000),sn);c.reloc(sn,1,'_public',20)
            c.section('.drectve',b' /alternatename:_public=_implementation /include:_matching_only ',0x100a00);c.write(p/'entry.obj')
            c=COFF();sn=c.section('.rdata',bytes(4));c.reloc(sn,0,label(0x401000),6);c.write(p/'image_data.obj')
            (p/'image_report.json').write_text(json.dumps(dict(tls_callbacks=[])))
            class Original:
                entry=0x401000
                def directory(self,n):return (0,0)
            counts=discard_unreachable(db,[p/'entry.obj',p/'impl.obj'],Original(),p)
            self.assertEqual(counts['compiler_matching_include_directives_dropped'],1)
            self.assertFalse(CoffView(p/'impl.obj').sections[1]['flags']&0x800)
            db.close()

    def test_bound_defined_code_uses_implementing_address(self):
        from standalone_common import append_symbols
        with tempfile.TemporaryDirectory(prefix='policy_code_owner_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE matched_reference(name TEXT,unit INTEGER)')
            db.execute('INSERT INTO matched_reference VALUES (?,?)',('_same',0))
            db.execute('INSERT INTO binding VALUES (?,?,?)',('_same',0x402000,0))
            comdat(p/'good.obj','_same',b'\xc3');append_symbols(p/'good.obj',p/'good.obj',[(label(0x402000),1,0)])
            comdat(p/'wrong.obj','_same',b'\xe8\0\0\0\0\xc3','_unbound')
            c=COFF();sn=c.section('.text',b'\xe8\0\0\0\0\xc3',0x60500020)
            c.symbol(label(0x401000),sn);c.reloc(sn,1,'_same',20);c.write(p/'entry.obj')
            c=COFF();sn=c.section('.rdata',bytes(4));c.reloc(sn,0,label(0x401000),6);c.write(p/'image_data.obj')
            (p/'image_report.json').write_text(json.dumps(dict(tls_callbacks=[])))
            class Original:
                entry=0x401000
                def relocations(self):return [(0x401001,0x405000)]
                def section(self,a):return dict(name='.text') if a in (0x401000,0x402000) else None
                def directory(self,n):return (0,0)
            paths=[p/'entry.obj',p/'good.obj',p/'wrong.obj']
            counts=canonical_code_references(db,paths,Original(),p)
            self.assertEqual(counts['rewritten_references'],1)
            discard_unreachable(db,paths,Original(),p)
            self.assertFalse(CoffView(p/'good.obj').sections[1]['flags']&0x800)
            self.assertTrue(CoffView(p/'wrong.obj').sections[1]['flags']&0x800)
            db.close()

    def test_conflicting_global_drops_compiler_owner_without_picking_address(self):
        with tempfile.TemporaryDirectory(prefix='policy_bound_conflict_') as folder:
            p=Path(folder);db=database(p/'state.sqlite');c=COFF()
            text=c.section('.text',b'\xb8\0\0\0\0\xc3',0x60500020);c.symbol('_entry',text)
            data=c.section('.rdata',bytes(4));index=c.symbol('_global',data);c.reloc(text,1,'_global',6)
            obj=p/'source.obj';c.write(obj)
            for a in (0x5000,0x5100):db.execute('INSERT INTO binding VALUES (?,?,?)',('_global',a,1))
            db.execute('INSERT INTO definition VALUES (?,?,?,?,?,?)',('_global',0,data,0,1,0))
            class Original:
                def section(self,a):return dict(name='.rdata',lo=0x5000,hi=0x6000) if 0x5000<=a<0x6000 else None
            plans=ownership(db,[dict(source='synthetic.cpp')],[obj],Original(),p)
            self.assertNotIn(index,plans[0]['symbols'])
            self.assertEqual(plans[0]['unresolved'][index]['name'],'_global')
            result=rewrite_objects(db,[obj],{},p,{},plans);view=CoffView(result[0])
            ti=view.sections[text]['relocs'][0][1]
            self.assertEqual(view.symbols[ti]['name'],'_global');self.assertEqual(view.symbols[ti]['section'],0)
            self.assertTrue(view.sections[data]['flags']&0x800)
            db.close()

    def test_static_literal_names_are_local_to_the_object(self):
        with tempfile.TemporaryDirectory(prefix='policy_literal_') as folder:
            p=Path(folder);db=database(p/'state.sqlite');c=COFF()
            text=c.section('.text',b'\xb8\0\0\0\0\xc3',0x60500020);c.symbol('_entry',text)
            data=c.section('.rdata',b'aaaa\0');literal=c.symbol('$SG1',data,0,storage=3);c.reloc(text,1,'$SG1',6)
            obj=p/'literal.obj';c.write(obj)
            db.execute('INSERT INTO binding VALUES (?,?,?)',('$SG1',0x5100,1))
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x401006,0,text,0,'_entry','function'))
            class Original:
                def section(self,a):return dict(name='.rdata',lo=0x5000,hi=0x6000) if 0x5000<=a<0x6000 else None
                def read(self,a,n):return struct.pack('<I',0x5000)
            plans=ownership(db,[dict(source='synthetic.cpp')],[obj],Original(),p)
            self.assertEqual(plans[0]['symbols'][literal],0x5000)
            db.close()

    def test_original_init_table_is_a_reachability_root(self):
        with tempfile.TemporaryDirectory(prefix='policy_roots_') as folder:
            p=Path(folder);db=database(p/'state.sqlite');comdat(p/'init.obj','_init',b'\xc3')
            c=COFF();sn=c.section('.text',b'\xc3',0x60500020);c.symbol(label(0x401000),sn);c.write(p/'image_code.obj')
            c=COFF();sn=c.section('.rdata',bytes(4));c.reloc(sn,0,'_init',6);c.write(p/'image_data.obj')
            (p/'image_report.json').write_text(json.dumps(dict(tls_callbacks=[])))
            class Original:
                entry=0x401000
                def directory(self,n):return (0,0)
            discard_unreachable(db,[p/'init.obj'],Original(),p)
            self.assertFalse(CoffView(p/'init.obj').sections[1]['flags']&0x800)
            db.close()


    def test_differing_comdats_are_reported_without_changes(self):
        with tempfile.TemporaryDirectory(prefix='policy_collision_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            comdat(p/'a.obj','_same',b'\xc3');comdat(p/'b.obj','_same',b'\x31\xc0\xc3')
            before=[(p/n).read_bytes() for n in ('a.obj','b.obj')]
            (p/'native_duplicates.json').write_text(json.dumps([dict(symbol='_same',object='b.obj',previous_object='a.obj')]))
            summary=reconcile_comdats(db,[p/'a.obj',p/'b.obj'],p)
            self.assertEqual(summary['differing_symbols'],1)
            self.assertEqual(before,[(p/n).read_bytes() for n in ('a.obj','b.obj')])
            db.close()

    def test_abi_is_warning_only_for_matched_reference(self):
        with tempfile.TemporaryDirectory(prefix='policy_alias_') as folder:
            p=Path(folder);db=database(p/'state.sqlite')
            db.execute('CREATE TABLE matched_reference(name TEXT,unit INTEGER)')
            for name,a in [('_f@4',0x401000),('_dead@4',0x401000)]:
                db.execute('INSERT INTO binding VALUES (?,?,?)',(name,a,0));db.execute('INSERT INTO reference VALUES (?,?)',(name,0))
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x401010,0,1,0,'_implementation@8','function'))
            db.execute('INSERT INTO address VALUES (?,?)',(0x401000,'recipe'))
            db.execute('INSERT INTO matched_reference VALUES (?,?)',('_f@4',0))
            counts=generate(db,p)
            self.assertEqual(counts,dict(ok_address=1,unproved_copy_reference=1))
            self.assertEqual(json.loads(db.execute('SELECT detail FROM alias WHERE name=?',('_f@4',)).fetchone()[0])['abi_warning'],'mismatch')
            db.close()

    def test_bound_mutable_owner_and_startup_drop(self):
        with tempfile.TemporaryDirectory(prefix='policy_owner_') as folder:
            p=Path(folder);db=database(p/'state.sqlite');c=COFF()
            text=c.section('.text',b'\xb8\0\0\0\0\xc3',0x60500020);c.symbol('_entry',text)
            data=c.section('.data',b'xxxx',0xc0300040);c.symbol('_global',data)
            c.reloc(text,1,'_global',6)
            startup=c.section('.CRT$XCU',bytes(4),0x40300040);c.reloc(startup,0,'_double_init',6)
            obj=p/'source.obj';c.write(obj)
            db.execute('INSERT INTO binding VALUES (?,?,?)',('_global',0x5000,0))
            db.execute('INSERT INTO definition VALUES (?,?,?,?,?,?)',('_global',0,data,0,0,0))
            db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x401006,0,text,0,'_entry','function'))
            class Original:
                def section(self,a):return dict(name='.data',lo=0x5000,hi=0x6000) if 0x5000<=a<0x6000 else None
                def read(self,a,n):return struct.pack('<I',0x5000)
            plans=ownership(db,[dict(source='synthetic.cpp')],[obj],Original(),p)
            result=rewrite_objects(db,[obj],{},p,{},plans);view=CoffView(result[0])
            self.assertTrue(view.sections[startup]['flags']&0x800)
            self.assertTrue(view.sections[data]['flags']&0x800)
            self.assertEqual(view.symbols[view.sections[text]['relocs'][0][1]]['name'],label(0x5000))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM definition').fetchone()[0],0)
            db.close()



if __name__=='__main__':unittest.main(verbosity=2)
