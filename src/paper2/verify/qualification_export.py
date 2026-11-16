"""Qualification-only export; never activates a production workflow."""
import argparse,ast,hashlib,io,json,os,shutil,subprocess,tarfile,gzip
from pathlib import Path
from src.paper2.model.service_times import ROOT,BASELINE,sha256_file
from src.paper2.prototype.export import frozen_closure,audit_payload,lint_workflow
from .qualification_regression import PIN

TESTS=('test_phase1_handchecks','test_phase2_state','test_phase3_corrections','test_phase3_policies',
       'test_phase5a_deviation9_a','test_phase5a_deviation9_b','_explicit_e50_reference')
WORKFLOW='paper2-model-qualification.yml'

def git(*args):
    command=shutil.which('git') or 'C:/Program Files/Git/cmd/git.exe'
    return subprocess.check_output([command,*args],cwd=ROOT)

def reference_files():
    available=set(git('ls-tree','-r','--name-only',PIN,'src').decode().splitlines());selected={};pending=['src/paper2/model/__init__.py']
    def add_module(name):
        for candidate in (name.replace('.','/')+'.py',name.replace('.','/')+'/__init__.py'):
            if candidate in available and candidate not in selected:pending.append(candidate)
        for i in range(1,len(name.split('.'))):
            candidate='/'.join(name.split('.')[:i])+'/__init__.py'
            if candidate in available and candidate not in selected:pending.append(candidate)
    while pending:
        rel=pending.pop()
        if rel in selected:continue
        raw=git('show',PIN+':'+rel);selected[rel]=raw;package=Path(rel).parent.parts
        for node in ast.walk(ast.parse(raw.decode('utf-8-sig'))):
            names=[]
            if isinstance(node,ast.Import):names=[v.name for v in node.names]
            elif isinstance(node,ast.ImportFrom):
                prefix='.'.join(package[:len(package)-node.level+1]) if node.level else ''
                name='.'.join(v for v in (prefix,node.module) if v);names=[name]+[name+'.'+v.name for v in node.names]
            for name in names:
                if name.startswith('src.'):add_module(name)
    return selected

def write_reference(destination):
    files=reference_files();path=Path(destination)/'qualification_inputs/reference-3538968.tar.gz'
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('wb') as stream,gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w|') as tar:
        for name,raw in sorted(files.items()):
            item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o644;item.mtime=0;tar.addfile(item,io.BytesIO(raw))
    descriptor=dict(commit=PIN,archive_sha256=sha256_file(path),files={p:hashlib.sha256(r).hexdigest() for p,r in sorted(files.items())})
    path.with_suffix('.json').write_text(json.dumps(descriptor,indent=2))
    return files

def unpack_reference(root,destination):
    root=Path(root);destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
    archive=root/'qualification_inputs/reference-3538968.tar.gz';spec=json.loads(archive.with_suffix('.json').read_text())
    if spec['commit']!=PIN or sha256_file(archive)!=spec['archive_sha256']:raise ValueError('reference seal mismatch')
    seen=set()
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar:
            target=(destination/member.name).resolve()
            if not member.isfile() or destination.resolve() not in target.parents or member.name not in spec['files']:raise ValueError('unsafe reference entry')
            raw=tar.extractfile(member).read()
            if member.name in seen or hashlib.sha256(raw).hexdigest()!=spec['files'][member.name]:raise ValueError('reference file mismatch')
            seen.add(member.name);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    if seen!=set(spec['files']):raise ValueError('reference files missing')
    return destination

def verify(root):
    root=Path(root);path=root/'QUALIFICATION_MANIFEST.json'
    if sha256_file(path)!=(root/'QUALIFICATION_MANIFEST.sha256').read_text().strip():raise ValueError('bundle manifest seal mismatch')
    spec=json.loads(path.read_text());expected=set(spec['files'])|{'QUALIFICATION_MANIFEST.json','QUALIFICATION_MANIFEST.sha256'}
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and '.git' not in p.relative_to(root).parts}
    if actual!=expected:raise ValueError('bundle inventory mismatch')
    for rel,digest in spec['files'].items():
        if sha256_file(root/rel)!=digest:raise ValueError('bundle payload mismatch: '+rel)
    return spec

def export(destination):
    destination=Path(destination).resolve()
    if ROOT==destination or ROOT in destination.parents or destination in ROOT.parents or destination.exists():raise ValueError('new external destination required')
    if git('status','--porcelain').strip():raise ValueError('clean source commit required')
    roots=list((ROOT/'src/paper2/verify').glob('qualification*.py'))
    roots += [ROOT/'tests/paper2'/str(name+'.py') for name in TESTS]
    roots += [ROOT/'src/paper2/verify/gate4b.py',ROOT/'src/paper2/model/__main__.py']
    selected=frozen_closure(roots)
    selected.update((ROOT/'tests/paper2/fixtures').glob('*.csv'));destination.mkdir()
    baseline={line.split('  ',1)[1]:line.split('  ',1)[0] for line in BASELINE.read_text().splitlines() if '  ' in line}
    for source in sorted(selected):
        rel=source.relative_to(ROOT).as_posix()
        if not rel.startswith(('src/paper2/','tests/paper2/')) and baseline.get(rel)!=sha256_file(source):raise ValueError('protected source mismatch: '+rel)
        target=destination/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(source.read_bytes())
    reference=write_reference(destination)
    # Audit historical reference source as text, not merely its compressed container.
    with __import__('tempfile').TemporaryDirectory() as temp:
        for rel,raw in reference.items():
            path=Path(temp)/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        audit_payload(temp,[dict(path=p) for p in reference])
    historical=ROOT/'results/revision_r1/cross_platform_20261021_130205/imports/calib-ARM64-rep1/calib-aarch64-rep1/raw_samples.csv'
    if baseline.get(historical.relative_to(ROOT).as_posix())!=sha256_file(historical):raise ValueError('G2 selector differs from frozen baseline')
    (destination/'qualification_inputs/G2_CALIBRATION.csv').write_bytes(historical.read_bytes())
    report=ROOT/'research/paper2/phase4/VERIFICATION_REPORT.md'
    prefix=report.read_bytes().split(b'\n## Execution evidence and gate status',1)[0]
    (destination/'qualification_inputs/G2_PREREGISTRATION.txt').write_bytes(prefix)
    target=destination/'.github/workflows'/WORKFLOW;target.parent.mkdir(parents=True);target.write_bytes((ROOT/'src/paper2/verify'/WORKFLOW).read_bytes())
    lint=lint_workflow(target)
    (destination/'requirements.txt').write_text('cryptography==45.0.7\n')
    (destination/'README.md').write_text('Research prototype for an unpublished study (Paper 2; Appiah, Opoku and Asare, Kumasi Technical University). Results are not yet published or peer-reviewed. This bundle activates only the manual paper2-model-qualification workflow: choose Actions, select that workflow, and Run workflow on main, with no inputs. SCALE, Phase C and G2 run sequentially; a failed gate stops qualification. Production validation remains blocked in the source; this bundle contains no production workflow.\n')
    (destination/'LICENSE').write_text('License to be decided by the authors before publication.\n')
    files={p.relative_to(destination).as_posix():sha256_file(p) for p in sorted(destination.rglob('*')) if p.is_file()}
    audit=audit_payload(destination,[dict(path=p) for p in files])
    production={p.name:sha256_file(p) for p in (ROOT/'src/paper2/prototype').glob('paper2-*.yml')}
    metadata=dict(schema='paper2-model-qualification-bundle-v1',source_commit=git('rev-parse','HEAD').decode().strip(),
        reference_commit=PIN,files=files,privacy=audit,actionlint=lint,production_templates_unchanged=production,
        g2_input='Frozen historical selector only; no calibration process is executed',qualification_only=True)
    path=destination/'QUALIFICATION_MANIFEST.json';path.write_text(json.dumps(metadata,indent=2,sort_keys=True))
    (destination/'QUALIFICATION_MANIFEST.sha256').write_text(sha256_file(path)+'\n');verify(destination)
    return metadata

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['export','verify']);p.add_argument('directory',type=Path);a=p.parse_args()
    print(json.dumps((export if a.action=='export' else verify)(a.directory),indent=2))

if __name__=='__main__':main()
