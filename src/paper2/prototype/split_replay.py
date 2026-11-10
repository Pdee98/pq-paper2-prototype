"""Strict union of completed 7X/7M parts; preserve global run/seed identities."""
import argparse
import os
from pathlib import Path
import shutil
from . import replay, artifact_integrity


def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if replay.sha256_file(source) != replay.sha256_file(destination):
            raise ValueError('conflicting split payload: '+destination.name)
        return
    try: os.link(source, destination)
    except OSError: shutil.copyfile(source, destination)


def union(xroot, mroot, output, xrun, mrun):
    output=Path(output)
    if output.exists():raise FileExistsError('union must be new')
    parts=[]
    for root, source, label, backend, ids in (
            (Path(xroot),str(xrun),'7X','xmss',set(range(8))|{16}),
            (Path(mroot),str(mrun),'7M','ml_dsa_44',set(range(8,16)))):
        artifact_integrity.verify_checksums(root)
        index=replay.verify(root,source)
        receipt=index.get('part_receipt',{})
        if receipt.get('part')!=label or receipt.get('operational_status')!='complete':
            raise ValueError('operationally incomplete or wrong part')
        if receipt.get('attempt') not in (1,2):raise ValueError('at most one operational re-run')
        cells=replay.cell_map(index)
        if set(cells)!=ids or any(c['backend']!=backend for c in cells.values()):
            raise ValueError('missing/wrong backend or changed global cell identity')
        if receipt.get('attempt')==2:
            previous=receipt.get('previous_attempt_evidence',{})
            if (previous.get('attempt')!=1 or previous.get('operational_status')!='failed' or
                    previous.get('preserved') is not True or previous.get('code_commit')!=index['code_commit']):
                raise ValueError('re-run must retain its failed attempt evidence from the same commit')
        parts.append((root,index))
    if parts[0][1]['code_commit']!=parts[1][1]['code_commit']:
        raise ValueError('split parts must use the same bundle commit')
    cells={i:c for _,index in parts for i,c in replay.cell_map(index).items()}
    index=dict(schema=replay.SCHEMA,code_commit=parts[0][1]['code_commit'],source_run_id=str(xrun),
        source_run_ids=[str(xrun),str(mrun)],cells=[cells[i] for i in sorted(cells)],
        cell_ids=sorted(cells),status=replay.PENDING,runs=[],excluded_cells=[],
        part_receipts=[idx['part_receipt'] for _,idx in parts],source_receipts=[])
    output.mkdir(parents=True)
    for root,part in parts:
        for run in part['runs']:
            index['runs'].append(dict(run,source_run_id=part['source_run_id']))
        index['excluded_cells'].extend(part['excluded_cells'])
        for file in sorted(root.rglob('*')):
            if not file.is_file() or file in (root/'INDEX.json',root/'INDEX.sha256',root/'SHA256SUMS'):continue
            copy_file(file,output/file.relative_to(root))
        replay.save(output/'source-receipts'/('part-'+part['part_receipt']['part']+'.json'),
                    dict(index_sha256=replay.sha256_file(root/'INDEX.json'),index=part))
    index['excluded_cells']=[dict(cell=c,reason=replay.EXCLUSION) for c in index['cells'] if c['dispatcher_utilisation']>.5]
    index['source_receipts']=[dict(path=file.relative_to(output).as_posix(),sha256=replay.sha256_file(file)) for file in sorted((output/'source-receipts').glob('*.json'))]
    replay.write_index(output,index)
    artifact_integrity.write_checksums(output)
    replay.verify(output,str(xrun))
    return index


def main():
    p=argparse.ArgumentParser()
    for name in ('xmss','ml-dsa','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--xmss-run-id',required=True);p.add_argument('--ml-dsa-run-id',required=True)
    a=p.parse_args();union(a.xmss,a.ml_dsa,a.output,a.xmss_run_id,a.ml_dsa_run_id)


if __name__=='__main__':main()
