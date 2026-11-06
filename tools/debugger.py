"""Bounded Windows debugger; reports unhandled exception symbols from the native map."""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import re,struct,time
from standalone_common import OUT,dump,hx,reserve

class StartupInfo(C.Structure):
    _fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),
        ('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),
        ('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('reserved2size',W.WORD),
        ('reserved2',C.c_void_p),('stdin',W.HANDLE),('stdout',W.HANDLE),('stderr',W.HANDLE)]



class ProcessInfo(C.Structure):
    _fields_=[('process',W.HANDLE),('thread',W.HANDLE),('pid',W.DWORD),('tid',W.DWORD)]



class DebugEvent(C.Structure):
    _fields_=[('code',W.DWORD),('pid',W.DWORD),('tid',W.DWORD),('data',C.c_uint64*20)]



def map_address(path,address):
    best=None
    if not Path(path).exists():return None
    for line in Path(path).read_text(errors='replace').splitlines():
        m=re.match(r'\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8})\b',line)
        if m:
            a=int(m[2],16)
            if a<=address and (best is None or a>best[0]):best=(a,m[1])
    return dict(symbol=best[1],offset=address-best[0],symbol_address=hx(best[0])) if best else None



def process_windows(pid):
    """Read visible top-level windows belonging to the bounded child only."""
    u=C.WinDLL('user32',use_last_error=True)
    callback_type=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
    u.EnumWindows.argtypes=[callback_type,W.LPARAM]
    u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
    u.IsWindowVisible.argtypes=[W.HWND]
    u.GetWindowTextW.argtypes=[W.HWND,W.LPWSTR,C.c_int]
    u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int]
    u.GetWindowRect.argtypes=[W.HWND,C.POINTER(W.RECT)]
    windows=[]
    def visit(hwnd,param):
        owner=W.DWORD();u.GetWindowThreadProcessId(hwnd,C.byref(owner))
        if owner.value==pid and u.IsWindowVisible(hwnd):
            title=C.create_unicode_buffer(512);kind=C.create_unicode_buffer(256);rect=W.RECT()
            u.GetWindowTextW(hwnd,title,512);u.GetClassNameW(hwnd,kind,256);u.GetWindowRect(hwnd,C.byref(rect))
            windows.append(dict(hwnd=hex(hwnd),title=title.value,class_name=kind.value,
                                rect=[rect.left,rect.top,rect.right,rect.bottom]))
        return True
    u.EnumWindows(callback_type(visit),0)
    return windows



def smoke(out=OUT,timeout=120,game_dir=None,on_start=None):
    reserve(256*1024**2)
    out=Path(out);exe=out/'FalloutNV_src.exe'
    game_dir=Path(game_dir).resolve()
    k=C.WinDLL('kernel32',use_last_error=True)
    k.CreateProcessW.argtypes=[W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,W.DWORD,
                              C.c_void_p,W.LPCWSTR,C.POINTER(StartupInfo),C.POINTER(ProcessInfo)]
    k.CreateProcessW.restype=W.BOOL
    k.WaitForDebugEvent.argtypes=[C.POINTER(DebugEvent),W.DWORD];k.WaitForDebugEvent.restype=W.BOOL
    k.ContinueDebugEvent.argtypes=[W.DWORD,W.DWORD,W.DWORD];k.ContinueDebugEvent.restype=W.BOOL
    k.TerminateProcess.argtypes=[W.HANDLE,W.UINT];k.TerminateProcess.restype=W.BOOL
    k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
    k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
    si=StartupInfo();si.cb=C.sizeof(si);si.flags=0
    pi=ProcessInfo();cmd=C.create_unicode_buffer('"'+str(exe)+'"')
    # DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW; no elevated/debug privileges.
    from standalone_common import PE
    image=PE(exe)
    preferred=image.base;actual_base=preferred;image_size=image.image_size
    del image
    created=k.CreateProcessW(str(exe),cmd,None,None,False,0x00000002,None,str(game_dir),C.byref(si),C.byref(pi))
    if not created:
        result=dict(launched=False,winerror=C.get_last_error(),cwd=str(game_dir))
        dump(out/'smoke_report.json',result);return result
    deadline=time.monotonic()+timeout;exceptions=[];exitcode=None;timed=False;stopped_ram=False
    loader_breaks=set();windows=[];next_window_scan=0
    try:
        if on_start:on_start(pi.pid)
        while True:
            if time.monotonic()>=next_window_scan:
                for window in process_windows(pi.pid):
                    if window not in windows:windows.append(window)
                next_window_scan=time.monotonic()+0.5
            if time.monotonic()>deadline:
                timed=True;k.TerminateProcess(pi.process,0x102);deadline=float('inf')
            if not stopped_ram and __import__('placelink').available_memory()<__import__('placelink').RESERVE:
                stopped_ram=True;k.TerminateProcess(pi.process,0x103)
            event=DebugEvent()
            if not k.WaitForDebugEvent(C.byref(event),100):
                if C.get_last_error()!=121:raise C.WinError(C.get_last_error())
                continue
            raw=bytes(event.data);continuation=0x10002
            if event.code==1:
                code=struct.unpack_from('<I',raw,0)[0];address=struct.unpack_from('<Q',raw,16)[0]
                chance=struct.unpack_from('<I',raw,152)[0]
                if code in (0x80000003,0x4000001f) and code not in loader_breaks:
                    loader_breaks.add(code)
                else:
                    mapping=map_address(out/'FalloutNV.map',address-actual_base+preferred) if actual_base<=address<actual_base+image_size else None
                    parameters=struct.unpack_from('<I',raw,24)[0]
                    info=[struct.unpack_from('<Q',raw,32+j*8)[0] for j in range(min(parameters,15))]
                    exceptions.append(dict(code=hx(code),address=hx(address),first_chance=bool(chance),
                                           mapping=mapping,parameters=list(map(hx,info)),
                                           ))
                    continuation=0x80010001 # DBG_EXCEPTION_NOT_HANDLED
                    if not chance:
                        # Record the unhandled fault and terminate before Windows
                        # Error Reporting can display a modal crash dialog.
                        k.TerminateProcess(pi.process,code)
            elif event.code==3:
                # CREATE_PROCESS_DEBUG_EVENT supplies a separate image-file
                # handle. The process/thread handles are the CreateProcess pair.
                handle=struct.unpack_from('<Q',raw,0)[0]
                if handle:k.CloseHandle(handle)
                # Debug-event process/thread handles belong to the debug session.
                # ContinueDebugEvent closes them at EXIT_PROCESS/EXIT_THREAD;
                # early CloseHandle can close unrelated reused handles later.
                actual_base=struct.unpack_from('<Q',raw,24)[0]
            elif event.code==2:
                pass # The debug-event thread handle is closed by EXIT_THREAD.
            elif event.code==6:
                handle=struct.unpack_from('<Q',raw,0)[0]
                if handle:k.CloseHandle(handle)
            elif event.code==5:
                exitcode=struct.unpack_from('<I',raw,0)[0]
            k.ContinueDebugEvent(event.pid,event.tid,continuation)
            if event.code==5:break
    finally:
        if exitcode is None:k.TerminateProcess(pi.process,0x104)
        k.WaitForSingleObject(pi.process,5000)
        k.CloseHandle(pi.thread);k.CloseHandle(pi.process)
    result=dict(launched=True,cwd=str(game_dir),timeout_seconds=timeout,timed_out=timed,
                stopped_for_RAM=stopped_ram,exit_code_hex=hx(exitcode) if exitcode is not None else None,
                windows=windows,exceptions=exceptions,first_error=exceptions[0] if exceptions else None)
    dump(out/'smoke_report.json',result);return result
