"""Local run guards for installed files and fixed-name saves."""
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,os
from pathlib import Path

FIXED_SAVES=('autosave.fos','autosave.fos.bak','quicksave.fos','quicksave.fos.bak','autosave.nvse','quicksave.nvse')


def documents_folder():
    folder=C.create_unicode_buffer(32768)
    shell=C.WinDLL('shell32',use_last_error=True)
    shell.SHGetFolderPathW.argtypes=[W.HWND,C.c_int,W.HANDLE,W.DWORD,W.LPWSTR]
    shell.SHGetFolderPathW.restype=C.c_long
    if shell.SHGetFolderPathW(None,5,None,0,folder):raise OSError('cannot locate Documents folder')
    return Path(folder.value)


def fixed_save_names(folder):
    return {p.name for p in folder.iterdir() if p.is_file()
            and p.name.lower().startswith(('autosave','quicksave'))} if folder.exists() else set()


class UnsupportedSaveLocation(RuntimeError):
    """The launcher cannot be sure where the game will write its saves, so it does not start the game."""


DEFAULT_SAVE_PATHS={'saves\\','saves/','saves'}
# Files the game reads these settings from, in the order it reads them; later files override earlier ones.
SAVE_SETTING_FILES=('Fallout_default.ini','Fallout.ini','FalloutPrefs.ini','FalloutCustom.ini')


def ini_settings(path,keys):
    """{key: [values]} for every assignment of the given keys in an ini file, any section, keys case-insensitive."""
    found={}
    for line in path.read_text(encoding='latin-1').splitlines():
        line=line.split(';',1)[0].strip()
        if '=' not in line or line.startswith('['):continue
        key,value=(part.strip() for part in line.split('=',1))
        if key.lower() in keys:found.setdefault(key.lower(),[]).append(value)
    return found


def find_file(folder,name):
    """The file in folder whose name matches case-insensitively, or None; more than one is ambiguous."""
    if not folder.is_dir():return None
    matches=[p for p in folder.iterdir() if p.is_file() and p.name.lower()==name.lower()]
    if len(matches)>1:raise UnsupportedSaveLocation('more than one %s in %s' % (name,folder))
    return matches[0] if matches else None


def resolve_save_dir(documents,game_dir):
    """The folder the game will save to, or UnsupportedSaveLocation. Only the default location is supported:
    Documents/My Games/FalloutNV/Saves, with SLocalSavePath=Saves\\ and bUseMyGamesDirectory unset or 1 in every
    settings file the game reads. Anything else (a custom or conflicting save path, saves in the game folder) is
    refused rather than guessed, because backing up the wrong folder would leave the real saves unprotected."""
    if documents is None:raise UnsupportedSaveLocation('cannot locate the Documents folder')
    my_games=Path(documents)/'My Games'/'FalloutNV'
    if not my_games.is_dir():
        raise UnsupportedSaveLocation('%s does not exist; start the original game once so it creates its settings'
                                      % my_games)
    keys={'slocalsavepath','bmygamesdirectory','busemygamesdirectory'}
    seen={}
    for name in SAVE_SETTING_FILES:
        path=find_file(Path(game_dir) if name=='Fallout_default.ini' else my_games,name)
        if path is None:continue
        for key,values in ini_settings(path,keys).items():
            for value in values:seen.setdefault(key,[]).append((path,value))
    problems=[]
    for path,value in seen.get('slocalsavepath',[]):
        if value.strip('"').lower() not in DEFAULT_SAVE_PATHS:
            problems.append('%s sets SLocalSavePath=%s' % (path,value))
    for key in ('bmygamesdirectory','busemygamesdirectory'):
        for path,value in seen.get(key,[]):
            if value.strip()!='1':problems.append('%s sets %s=%s' % (path,key,value))
    if problems:
        raise UnsupportedSaveLocation('saves are not in the default location, so the launcher cannot protect them: '
                                      +'; '.join(problems)+'. Only the default Saves\\ folder is supported.')
    return my_games/'Saves'


class SaveGuard:
    def __init__(self,saves,backup,report):
        self.saves=Path(saves);self.backup=Path(backup);self.report=Path(report)

    def copy(self,source,target):
        target.write_bytes(source.read_bytes())

    def __enter__(self):
        """Back up every fixed-name save and read each copy back before anything starts; any failure stops here,
        before the game is launched, and the original saves are left as they were."""
        self.backup.mkdir(parents=True,exist_ok=False);self.before={}
        for name in sorted(set(FIXED_SAVES)|fixed_save_names(self.saves)):
            path=self.saves/name
            if path.exists():
                stat=path.stat();data=path.read_bytes()
                self.copy(path,self.backup/name)
                self.before[name]=dict(sha256=hashlib.sha256(data).hexdigest(),
                                      atime_ns=stat.st_atime_ns,mtime_ns=stat.st_mtime_ns)
            else:self.before[name]=None
        (self.backup/'before.json').write_text(json.dumps(self.before,indent=2))
        self.verify_backup()
        return self

    def verify_backup(self):
        problems=[]
        for name,old in self.before.items():
            if old is None:continue
            try:
                if hashlib.sha256((self.backup/name).read_bytes()).hexdigest()!=old['sha256']:
                    problems.append(name+': copy differs')
            except OSError as exc:problems.append('%s: %s' % (name,exc))
        try:
            if json.loads((self.backup/'before.json').read_text())!=self.before:problems.append('before.json differs')
        except (OSError,ValueError) as exc:problems.append('before.json: %s' % exc)
        if problems:
            raise RuntimeError('save backup could not be verified, so the game was not started; your saves were '
                               'not touched. Backup folder: %s. Problems: %s' % (self.backup,'; '.join(problems)))

    def __exit__(self,*exception):
        errors=[];rows=[]
        for name in fixed_save_names(self.saves)-self.before.keys():self.before[name]=None
        for name,old in self.before.items():
            path=self.saves/name
            try:
                now=path.read_bytes() if path.exists() else None
                prior=(self.backup/name).read_bytes() if old else None
                if old and hashlib.sha256(prior).hexdigest()!=old['sha256']:
                    raise RuntimeError('saved backup checksum changed')
                if now!=prior:
                    if now is not None:(self.backup/(name+'.test-output')).write_bytes(now)
                    if prior is None:path.unlink(missing_ok=True)
                    else:path.write_bytes(prior)
                if old:os.utime(path,ns=(old['atime_ns'],old['mtime_ns']))
                found=path.read_bytes() if path.exists() else None
                passed=found==prior and (not old or path.stat().st_mtime_ns==old['mtime_ns'])
                if not passed:raise RuntimeError('restored bytes/timestamp differ')
                rows.append(dict(name=name,passed=True,existed=bool(old)))
            except Exception as exc:errors.append(dict(name=name,error=str(exc)))
        self.report.write_text(json.dumps(dict(passed=not errors,backup=str(self.backup),files=rows,errors=errors),indent=2))
        if errors:
            # The backup folder is never deleted; say exactly where the user's original saves are.
            raise SaveRestoreFailed('RESTORE FAILED: your original autosave/quicksave files were NOT all put back. '
                                    'Copies of the originals are kept in %s (before.json lists their checksums). '
                                    'Copy them back into %s yourself before playing. Details: %s'
                                    % (self.backup,self.saves,'; '.join('%s: %s' % (e['name'],e['error'])
                                                                         for e in errors)))


class SaveRestoreFailed(RuntimeError):
    """Restoring the fixed-name saves failed; the backup folder was kept."""


class ReadOnlyInstallGuard:
    def __init__(self, paths):
        self.paths = paths
        self.handles = []
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p,
                                      W.DWORD, W.DWORD, W.HANDLE]
        self.k.CreateFileW.restype = W.HANDLE
        self.k.CloseHandle.argtypes = [W.HANDLE]

    def __enter__(self):
        try:
            for path in self.paths:
                h = self.k.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x80, None)
                if h == C.c_void_p(-1).value:
                    raise C.WinError(C.get_last_error())
                self.handles.append(h)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *unused):
        for h in reversed(self.handles):
            self.k.CloseHandle(h)
        self.handles.clear()
