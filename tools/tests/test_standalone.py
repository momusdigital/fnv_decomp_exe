"""Focused regression tests for the native linker boundary; no game bytes used."""
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from gen_aliases import abi,compatible,weak_aliases
from standalone_common import COFF,OUT
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'decomp'/'tools'))
import placelink as place
from standalone import tool


class StandaloneTests(unittest.TestCase):

    def test_late_generated_entry_relocates_earlier_fragment(self):
        from collections import Counter
        from gen_image import Generator
        from standalone_common import database
        from phase2_policy import CoffView as Coff
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        # Fragment B initially ends at RET. Fragment C later discovers B+1,
        # whose CALL to fragment A must be rescanned and relocated.
        class Original:
            base=0x400000
            header_size=0x400
            sections=[dict(name='.text',lo=0x401000,virtual_size=0x26)]
            def read(self,a,n):return code[a-0x401000:a-0x401000+n]
        code=bytearray(b'\xcc'*0x26)
        code[0]=0xc3
        code[0x10:0x17]=b'\xc3\xe8'+struct.pack('<i',0x401000-0x401016)+b'\xc3'
        code[0x20:0x26]=b'\xe8'+struct.pack('<i',0x401011-0x401025)+b'\xc3'
        with tempfile.TemporaryDirectory(prefix='late_entry_') as folder:
            d=Path(folder);db=database(d/'state.sqlite')
            try:
                g=Generator.__new__(Generator)
                g.db=db;g.pe=Original();g.out=d
                g.covered=[[0x401001,0x401010],[0x401017,0x401020]]
                g.highlow={};g.counts=Counter();g.targets=set()
                g.md=Cs(CS_ARCH_X86,CS_MODE_32);g.md.detail=True
                g.code_fixed_point()
                c=Coff(d/'image_code.obj')
                refs=[c.symbols[ti]['name'] for sec in c.sections[1:] for off,ti,kind in sec['relocs'] if kind==20]
                self.assertIn('_fnv_va_00401000',refs)
                self.assertIn('_fnv_va_00401011',refs)
                self.assertGreater(g.counts['code_discovery_passes'],1)
                self.assertEqual(g.counts['generated_code_bytes'],14)
            finally:db.close()

    def test_generated_storage_preserves_sse_alignment(self):
        from collections import Counter
        from gen_image import Generator
        from standalone_common import database, label
        from phase2_policy import CoffView
        class Original:
            base=0x400000
            header_size=0x400
            sections=[dict(name='.rdata',lo=0x402003,virtual_size=29,raw_size=29,pagehi=0x403000)]
            def read(self,a,n):return bytes(range(29))[a-0x402003:a-0x402003+n]
            def directory(self,n):return 0,0
        with tempfile.TemporaryDirectory(prefix='data_align_') as folder:
            d=Path(folder);db=database(d/'state.sqlite')
            try:
                db.execute('INSERT INTO address VALUES (?,?)',(0x402010,'test'))
                g=Generator.__new__(Generator)
                g.db=db;g.pe=Original();g.out=d;g.parts=[]
                g.highlow={0x402004:0x402010};g.counts=Counter();g.targets=set()
                g.data()
                c=CoffView(d/'image_data.obj')
                target=next(t for t in c.symbols.values() if t['name']==label(0x402010))
                sec=c.sections[target['section']]
                self.assertEqual((sec['flags']>>20)&15,5) # COFF alignment 16
                self.assertEqual(target['value'],16)
                self.assertEqual(target['value']%16,0x402010%16)
                self.assertEqual(sec['relocs'][0][0],4)
                self.assertEqual(c.data[sec['raw']:sec['raw']+3],bytes(3))
                self.assertEqual(g.counts['initialized_data_bytes'],29)
                self.assertEqual(g.counts['data_alignment_padding_bytes'],3)
            finally:db.close()

    def test_calling_convention_and_cleanup(self):
        self.assertEqual(compatible('_f@4','_g@4')[0],'ok')
        self.assertEqual(compatible('_f@4','_g@8')[0],'mismatch')
        self.assertEqual(compatible('_f@4','_g')[0],'mismatch')
        self.assertEqual(compatible('_f','_g')[0],'ok')
        self.assertEqual(abi('@f@8')['cleanup'],None)
        self.assertEqual(compatible('not_decorated','_f')[0],'unverified')
        self.assertEqual(abi('?GetType@NiRenderedTexture@@QAEPAVNiRTTI@@XZ')['convention'],'thiscall')


    def test_overlapping_tls_views_use_proven_offsets(self):
        from standalone_common import database
        from standalone import canonical_tls,rewrite_objects
        from compare import Coff
        OUT.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='tls_views_') as folder:
            d=Path(folder);c=COFF();text=c.section('.text',b'\xb8\0\0\0\0\xb9\0\0\0\0\xc3',0x60500020)
            c.symbol('_entry',text,0);tls=c.section('.tls$',bytes(8),0xc0300040)
            c.symbol('_view_a',tls,0);c.symbol('_view_b',tls,4)
            c.reloc(text,1,'_view_a',11);c.reloc(text,6,'_view_b',11)
            obj=d/'source.obj';c.write(obj)
            class Original:
                sections=[dict(name='.tls',lo=0x1272000,hi=0x1272004)]
                def read(self,a,n):return bytes(n)
            db=database(d/'state.sqlite')
            try:
                db.execute('INSERT INTO span VALUES (?,?,?,?,?,?,?)',(0x401000,0x40100b,0,1,0,'_entry','function'))
                plans=canonical_tls(db,[obj],Original(),d)
                self.assertEqual(set(plans[0]['symbols'].values()),{0x1272000})
                self.assertEqual(len(plans[0]['symbols']),2)
                result=rewrite_objects(db,[obj],{},d,plans)
                rewritten=Coff(result[0]);names=[rewritten.symbols[ti]['name'] for off,ti,kind in rewritten.sections[1]['relocs']]
                self.assertEqual(names,['_fnv_va_01272000']*2)
                self.assertTrue(rewritten.sections[2]['flags']&0x800)
            finally:db.close()









if __name__=='__main__':unittest.main(verbosity=2)
