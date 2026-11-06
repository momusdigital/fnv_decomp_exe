"""Pipeline refusal and restoration contracts, using synthetic inputs only."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'decomp'/'tools'))
import custom_exe
from run_guards import SaveGuard


class PipelineTests(unittest.TestCase):
    def test_compiler_count_refreshes_reused_windows_pids(self):
        import placelink
        class Snapshot:
            stale=True
            def cache_clear(self):self.stale=False
            def __call__(self,attributes):
                names=['cl.exe']*9 if self.stale else ['cl.exe','python.exe',None]
                return [SimpleNamespace(info=dict(name=n)) for n in names]
        with patch.object(placelink.psutil,'process_iter',Snapshot()):
            self.assertEqual(placelink.compiler_count(),1)

    def test_wrong_fingerprints_refuse_before_any_output(self):
        class UnrelatedImage:
            def read(self,address,size):return bytes(size)
        with tempfile.TemporaryDirectory() as d:
            image=Path(d)/'synthetic.exe';image.write_bytes(b'synthetic fixture')
            with patch('compare.Pe',return_value=UnrelatedImage()), patch('shutil.copyfile') as copy:
                with self.assertRaisesRegex(ValueError,'IMAGE CHECK FAILED'):
                    custom_exe.extract(SimpleNamespace(image=image,jobs=1))
                copy.assert_not_called()

    def test_source_digest_ignores_local_artifacts_and_detects_header_edits(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'include').mkdir();h=root/'include/test.h';h.write_text('struct Test {};')
            with patch.object(custom_exe,'ROOT',root):
                before=custom_exe.source_digest()
                (root/'.local').mkdir();(root/'.local/input.exe').write_bytes(b'synthetic')
                self.assertEqual(before,custom_exe.source_digest())
                h.write_text('struct Test { int value; };')
                self.assertNotEqual(before,custom_exe.source_digest())

    def test_save_guard_restores_bytes_times_and_absence_after_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);saves=root/'saves';saves.mkdir();p=saves/'autosave.fos';p.write_bytes(b'synthetic old save')
            os.utime(p,ns=(1234567890000000000,1234567890000000000));before=p.stat().st_mtime_ns
            with self.assertRaisesRegex(RuntimeError,'synthetic failure'):
                with SaveGuard(saves,root/'backup',root/'checks.json'):
                    p.write_bytes(b'synthetic changed save');(saves/'quicksave.fos').write_bytes(b'temporary')
                    raise RuntimeError('synthetic failure')
            self.assertEqual(p.read_bytes(),b'synthetic old save')
            self.assertEqual(p.stat().st_mtime_ns,before)
            self.assertFalse((saves/'quicksave.fos').exists())
            self.assertEqual((root/'backup/autosave.fos.test-output').read_bytes(),b'synthetic changed save')

    # --- save location and backup guards: the game must never start unless the saves are safely backed up ---

    def synthetic_profile(self,root,prefs=None,game_default='[General]\nSLocalSavePath=Saves\\\n'):
        documents=root/'Documents';my_games=documents/'My Games'/'FalloutNV';saves=my_games/'Saves'
        saves.mkdir(parents=True);game=root/'game';game.mkdir()
        (game/'Fallout_default.ini').write_text(game_default)
        (my_games/'Fallout.ini').write_text('[General]\nSLocalSavePath=Saves\\\n')
        if prefs is not None:(my_games/'FalloutPrefs.ini').write_text(prefs)
        (saves/'autosave.fos').write_bytes(b'synthetic autosave');(saves/'quicksave.fos').write_bytes(b'synthetic quick')
        return documents,game,saves

    def test_default_save_location_is_resolved(self):
        from run_guards import resolve_save_dir
        with tempfile.TemporaryDirectory() as d:
            documents,game,saves=self.synthetic_profile(Path(d),prefs='[General]\nSLocalSavePath=Saves\\\n')
            self.assertEqual(resolve_save_dir(documents,game),saves)

    def test_custom_or_conflicting_save_path_is_refused(self):
        from run_guards import UnsupportedSaveLocation, resolve_save_dir
        cases={'custom path':'[General]\nSLocalSavePath=Saves\\Other\\\n',
               'conflicts with Fallout.ini':'[General]\nSLocalSavePath=D:\\elsewhere\\\n',
               'saves outside My Games':'[General]\nbUseMyGamesDirectory=0\n'}
        for label,prefs in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                documents,game,saves=self.synthetic_profile(Path(d),prefs=prefs)
                with self.assertRaisesRegex(UnsupportedSaveLocation,'not in the default location'):
                    resolve_save_dir(documents,game)

    def test_missing_profile_or_documents_is_refused(self):
        from run_guards import UnsupportedSaveLocation, resolve_save_dir
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(UnsupportedSaveLocation,'does not exist'):
                resolve_save_dir(Path(d),Path(d))
            with self.assertRaisesRegex(UnsupportedSaveLocation,'Documents'):
                resolve_save_dir(None,Path(d))

    def test_run_refuses_unsupported_location_before_starting_the_game(self):
        import json, run
        from run_guards import UnsupportedSaveLocation
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);documents,game,saves=self.synthetic_profile(root,prefs='[General]\nSLocalSavePath=Elsewhere\\\n')
            (game/'FalloutNV.exe').write_bytes(b'synthetic');(game/'Data').mkdir();local=root/'local';local.mkdir()
            (local/'static_checks.json').write_text('{"passed": true}');(local/'FalloutNV_src.exe').write_bytes(b'x')
            (local/'build_result.json').write_text(json.dumps(dict(passed=True,source_digest='s',
                                                                   exe_sha256=hashlib.sha256(b'x').hexdigest())))
            with patch.object(run,'LOCAL',local), patch.object(run,'documents_folder',return_value=documents), \
                 patch('custom_exe.source_digest',return_value='s'), patch.object(run,'guarded_launch') as launch, \
                 patch('debugger.smoke') as smoke:
                with self.assertRaises(UnsupportedSaveLocation):
                    run.run(game,timeout=5)
                launch.assert_not_called();smoke.assert_not_called()
            self.assertFalse((local/'runs').exists())
            self.assertEqual((saves/'autosave.fos').read_bytes(),b'synthetic autosave')

    def guarded(self,saves,backup,start,guard=SaveGuard):
        import run
        class NoLock:
            def __init__(self,paths):pass
            def __enter__(self):return self
            def __exit__(self,*a):pass
        with patch.object(run,'ReadOnlyInstallGuard',NoLock):
            return run.guarded_launch(saves,backup,[],start,guard=guard)

    def test_backup_that_does_not_read_back_stops_before_launch(self):
        class CorruptingGuard(SaveGuard):
            def copy(self,source,target):target.write_bytes(source.read_bytes()+b'!')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);documents,game,saves=self.synthetic_profile(root);started=[]
            with self.assertRaisesRegex(RuntimeError,'could not be verified, so the game was not started'):
                self.guarded(saves,root/'run',lambda:started.append(True),guard=CorruptingGuard)
            self.assertEqual(started,[])
            self.assertEqual((saves/'autosave.fos').read_bytes(),b'synthetic autosave')
            self.assertEqual((saves/'quicksave.fos').read_bytes(),b'synthetic quick')

    def test_backup_write_error_stops_before_launch(self):
        class FailingGuard(SaveGuard):
            def copy(self,source,target):raise OSError('synthetic disk full')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);documents,game,saves=self.synthetic_profile(root);started=[]
            with self.assertRaisesRegex(OSError,'synthetic disk full'):
                self.guarded(saves,root/'run',lambda:started.append(True),guard=FailingGuard)
            self.assertEqual(started,[])
            self.assertEqual((saves/'autosave.fos').read_bytes(),b'synthetic autosave')

    def test_saves_restored_after_simulated_game_failure(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);documents,game,saves=self.synthetic_profile(root)
            def crashing_game():
                (saves/'autosave.fos').write_bytes(b'written by the test run')
                (saves/'autosave.fos.bak').write_bytes(b'new file')
                raise RuntimeError('synthetic game crash')
            with self.assertRaisesRegex(RuntimeError,'synthetic game crash'):
                self.guarded(saves,root/'run',crashing_game)
            self.assertEqual((saves/'autosave.fos').read_bytes(),b'synthetic autosave')
            self.assertFalse((saves/'autosave.fos.bak').exists())
            self.assertTrue(json.loads((root/'run/save_checks.json').read_text())['passed'])

    def test_failed_restore_keeps_backup_and_reports_its_location(self):
        import json
        from run_guards import SaveRestoreFailed
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);documents,game,saves=self.synthetic_profile(root);backup=root/'run'/'saves'
            def game_that_blocks_restore():
                # A folder where the save file was, so writing the original back fails.
                (saves/'autosave.fos').unlink();(saves/'autosave.fos').mkdir()
            with self.assertRaises(SaveRestoreFailed) as caught:
                self.guarded(saves,root/'run',game_that_blocks_restore)
            message=str(caught.exception)
            self.assertIn('RESTORE FAILED',message);self.assertIn(str(backup),message)
            self.assertEqual((backup/'autosave.fos').read_bytes(),b'synthetic autosave')
            self.assertFalse(json.loads((root/'run/save_checks.json').read_text())['passed'])

    def test_map_lookup_reports_symbol_and_offset(self):
        from debugger import map_address
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'synthetic.map';p.write_text(' 0001:00000000 _synthetic_entry 00401000 f synthetic.obj\n')
            self.assertEqual(map_address(p,0x401003)['symbol'],'_synthetic_entry')
            self.assertEqual(map_address(p,0x401003)['offset'],3)
            self.assertIsNone(map_address(p,0x400fff))


if __name__=='__main__':unittest.main()
