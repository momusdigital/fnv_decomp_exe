#!/usr/bin/env python3
"""Build a local custom exe from checked source and the owner's plain executable.

All derived material stays under the ignored .local/custom-exe directory.
Windows only; the native link pipeline has not been tested under Wine.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'decomp' / 'tools'))
from config import ROOT, LOCAL, IMAGE, TC, compiler_environment


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_digest():
    h = hashlib.sha256()
    for folder in ('src', 'include', 'build', 'tools', 'third_party'):
        for p in sorted((ROOT / folder).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:
                h.update(p.relative_to(ROOT).as_posix().encode())
                h.update(p.read_bytes())
    return h.hexdigest()


def checked_image(path):
    from build_and_match import image_ok
    from compare import Pe
    ok, hits, total = image_ok(Pe(path))
    if not ok:
        raise ValueError('IMAGE CHECK FAILED (%d/%d): supply your own plain PC 1.4.0.525 exe; see README.md' % (hits, total))
    return hits, total


def validate_objects(units, objects, image):
    """Check compiled functions and locate EH without private placement inventories."""
    from build_and_match import recipe_names, eh_sections, eh_tails
    from compare import Coff, compare
    from function_spans import FunctionSpans
    from standalone_common import dump
    index = ROOT / 'build/function_index.json'
    spans = FunctionSpans.from_index(image.pe, index) if index.exists() else None
    names = recipe_names(units); accepted = {}; results = []
    for i, (unit, obj) in enumerate(zip(units, objects)):
        c = Coff(obj)
        manifest = dict(unit)
        rows = compare(c, image.pe, manifest, spans)
        if any(row['verdict'] != 'match' for row in rows):
            raise ValueError('compiled functions do not match: ' + unit['source'])
        sections, inferred, errors = eh_sections(c, image.pe, unit, rows, names) if unit.get('eh_tails') else ([],{},[])
        accepted[i] = [(lo, hi-lo) for lo,hi,ok,_,_ in sections if ok]
        results.append(dict(eh_sections=sections, eh_inferred={k:'0x%08x'%v for k,v in inferred.items()}))
        if i % 250 == 0: print('Validate %d/%d' % (i,len(units)), flush=True)
    tails, bad, inferred, n, conflicts = eh_tails(units, results, image.pe)
    if bad or conflicts: raise ValueError('EH tails do not match')
    dump(LOCAL / 'accepted_eh.json', accepted)
    dump(LOCAL / 'source_checks.json', dict(passed=True, functions=sum(len(u['functions']) for u in units),
                                         eh_tails=len(tails), eh_tail_bytes=sum(tails.values())))


def extract(args):
    # Validate before creating any output. The input is only ever opened for reading.
    image = args.image.resolve()
    if image.is_relative_to(LOCAL): raise ValueError('input must be outside the output directory')
    hits, total = checked_image(image)
    initial_source=source_digest()
    LOCAL.mkdir(parents=True, exist_ok=True)
    (LOCAL/'extraction.json').unlink(missing_ok=True)
    (LOCAL/'build_result.json').unlink(missing_ok=True)
    (LOCAL/'FalloutNV_src.exe').unlink(missing_ok=True)
    from standalone_common import PE, database, dump, reserve
    import placelink as place
    import standalone as S
    from binding_policy import reconcile_bindings
    from phase2_policy import ownership
    from gen_image import Generator
    from data_source import emit
    reserve()
    original_hash=digest(image)
    # A private validation oracle is retained so subsequent static checks do not
    # depend on the installation. It is never a distributable build input.
    shutil.copyfile(image, IMAGE)
    pe=PE(IMAGE);env=compiler_environment();units=place.load_recipe(ROOT)
    objects, stats=place.build_objects(ROOT, units, env, args.jobs)
    validate_objects(units,objects,pe)
    db=database()
    S.setup(db,units)
    candidates=S.index_objects(db,units,objects,pe,LOCAL)
    reconcile_bindings(db,objects,pe,LOCAL)
    plans=S.reconcile_data(db,units,objects,pe,candidates,LOCAL)
    tls=S.canonical_tls(db,objects,pe,LOCAL)
    policy=ownership(db,units,objects,pe,LOCAL)
    reconcile_bindings(db,objects,pe,LOCAL,accumulate=True)
    libs=S.imports(db,pe,LOCAL,env)
    generated=Generator(db,IMAGE,LOCAL).run()
    (LOCAL/'data').mkdir(exist_ok=True)
    emit(SimpleNamespace(out=LOCAL/'data',input=LOCAL/'image_data.obj',state=LOCAL/'state.sqlite',chunk=32768))
    if source_digest()!=initial_source:raise RuntimeError('source changed during extraction; run extract again')
    dump(LOCAL/'objects.json',list(map(str,objects)))
    dump(LOCAL/'extraction.json',dict(version=1,source_digest=source_digest(),image_sha256=original_hash,
         fingerprint_hits=hits,fingerprint_probes=total,compile=stats,libraries=libs,
         data_plans=plans,tls_plans=tls,policy_plans=policy,generated=generated,
         object_hashes={str(p):digest(p) for p in objects}))
    db.close()
    if digest(image)!=original_hash: raise RuntimeError('input changed during extraction')
    print('Extracted private build inputs to ' + str(LOCAL),flush=True)


def numeric_keys(value):
    if isinstance(value,dict): return {(int(k) if str(k).isdigit() else k):numeric_keys(v) for k,v in value.items()}
    if isinstance(value,list): return [numeric_keys(v) for v in value]
    return value


def build(args):
    from standalone_common import PE, database, dump
    import standalone as S
    from data_source import compile_sources
    from phase2_policy import canonical_code_references, discard_unreachable, trim_unmatched_eh, reconcile_comdats
    (LOCAL/'build_result.json').unlink(missing_ok=True)
    (LOCAL/'FalloutNV_src.exe').unlink(missing_ok=True)
    metadata=json.loads((LOCAL/'extraction.json').read_text())
    if source_digest()!=metadata['source_digest']:
        raise ValueError('source or recipe changed; run extract again')
    checked_image(IMAGE)
    if digest(IMAGE)!=metadata['image_sha256']: raise ValueError('extracted oracle changed; run extract again')
    compile_sources(SimpleNamespace(out=LOCAL/'data',input=LOCAL/'image_data.obj',toolchain=TC))
    env=compiler_environment();pe=PE(IMAGE);db=database()
    from gen_aliases import generate
    generate(db,LOCAL)
    objects=[Path(p) for p in json.loads((LOCAL/'objects.json').read_text())]
    if any(metadata['object_hashes'].get(str(p))!=digest(p) for p in objects):
        raise ValueError('compiled objects changed; run extract again')
    native=S.rewrite_objects(db,objects,numeric_keys(metadata['data_plans']),LOCAL,
                            numeric_keys(metadata['tls_plans']),numeric_keys(metadata['policy_plans']))
    canonical_code_references(db,native,pe,LOCAL)
    discard_unreachable(db,native,pe,LOCAL)
    trimmed=trim_unmatched_eh(db,native,LOCAL)
    if trimmed.get('objects_changed'):discard_unreachable(db,native,pe,LOCAL,accumulate=True)
    S.current_blockers(db,LOCAL)
    linked=S.link(native,metadata['libraries'],pe,LOCAL,env,[n for n, in db.execute('SELECT DISTINCT symbol FROM import')])
    diagnostics=S.native_diagnostics(db,LOCAL)
    if diagnostics['duplicate_events']:
        reconciled=reconcile_comdats(db,native,LOCAL)
        if reconciled['identical_symbols']:
            discard_unreachable(db,native,pe,LOCAL,accumulate=True)
            linked=S.link(native,metadata['libraries'],pe,LOCAL,env,[n for n, in db.execute('SELECT DISTINCT symbol FROM import')])
            S.native_diagnostics(db,LOCAL)
    from phase2_policy import source_side_report
    source_side_report(db,objects,LOCAL)
    checks=S.static_checks(db,pe,LOCAL,linked)
    if not checks['passed']:raise RuntimeError('static checks failed; see '+str(LOCAL/'static_checks.json'))
    from audits import map_symbols, storage_audit, storage_highlow_audit, tls_audit
    from resources import resource_audit
    from pe_headers import audit as header_audit
    actual=PE(LOCAL/'FalloutNV.candidate.exe');symbols=map_symbols(LOCAL/'FalloutNV.map')
    manifest=json.loads((LOCAL/'data/data_manifest.json').read_text())
    extra=dict(storage=storage_audit(manifest,LOCAL/'image_data.obj',actual,symbols),
               storage_pointers=storage_highlow_audit(manifest,pe,actual,symbols),tls=tls_audit(pe,actual),
               resources=resource_audit(pe,actual),headers=header_audit(pe,actual))
    dump(LOCAL/'equivalence_checks.json',extra)
    if not all(x['passed'] for x in extra.values()):raise RuntimeError('equivalence checks failed')
    if source_digest()!=metadata['source_digest']:raise RuntimeError('source changed during build; run extract again')
    db.close()
    output=LOCAL/'FalloutNV_src.exe'
    shutil.copyfile(LOCAL/'FalloutNV.candidate.exe',output)
    dump(LOCAL/'build_result.json',dict(passed=True,source_digest=source_digest(),exe_sha256=digest(output)))
    print('Static checks PASS. Built '+str(output),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    commands=p.add_subparsers(dest='command',required=True)
    e=commands.add_parser('extract',help='validate the plain exe, compile checked objects, extract missing pieces locally')
    e.add_argument('--image',required=True,type=Path)
    e.add_argument('--jobs',type=int,choices=range(1,9),default=4)
    commands.add_parser('build',help='compile extracted C++ storage, link and statically validate')
    r=commands.add_parser('run',help='run the custom exe under a bounded crash-recording debugger')
    r.add_argument('--game-dir',required=True,type=Path)
    r.add_argument('--timeout',type=int,default=120)
    args=p.parse_args()
    if os.name!='nt':p.error('Windows is supported; this pipeline is untested under Wine')
    if sys.maxsize<2**32:p.error('use 64-bit Python 3.10 or newer')
    try:
        if args.command=='extract':extract(args)
        elif args.command=='build':build(args)
        else:
            from run import run
            run(args.game_dir,args.timeout)
    except (ValueError,RuntimeError,OSError) as exc:
        print(str(exc),file=sys.stderr);return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
