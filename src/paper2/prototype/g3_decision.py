"""Author D1-D3 decision rule. Pure aggregation; never dispatches a follow-up."""
import statistics
from .analysis import BANDS, compare
from .cycle_protocol import regime_category

STATUS={'PASS':'passed','FAIL':'failed','INCONCLUSIVE':'inconclusive'}


def repetition(result):
    validity=result.get('prototype',{}).get('validity')
    row=dict(run_id=result['run_id'],cell_id=result['cell_id'],replicate=result['replicate'],
             prototype_validity=validity,failures=[])
    proto=result.get('prototype',{})
    for violation in proto.get('violations',[]):
        row['failures'].append(dict(check='prototype invariant',violation=violation))
    valid=isinstance(validity,dict) and validity.get('passed') is True
    row.update(valid=valid,status='VALID' if valid else 'INVALID')
    if not valid:
        row['failing_guards']=validity if validity is not None else dict(reason='missing validity receipt')
        return row
    try:
        primary=compare(proto['metrics'],result['primary']['metrics'])
        held=compare(proto['metrics'],result['held_out']['metrics'],diagnostic=True)
        row.update(primary=primary,held_out=held)
        for name,check in primary['checks'].items():
            if not check['passed']:row['failures'].append(dict(check=name,**check))
        if not proto['metrics']['complete'] or not result['primary']['metrics']['complete']:
            row['failures'].append(dict(check='incomplete primary/prototype'))
        # Held-out bands remain diagnostic; full-mode invariants remain mandatory.
        for name in ('primary','held_out'):
            for violation in result[name]['violations']:
                row['failures'].append(dict(check=name+' invariant',violation=violation))
        if result.get('execution_error'):row['failures'].append(dict(check='execution',detail=result['execution_error']))
    except (KeyError,TypeError) as exc:
        row['failures'].append(dict(check='missing result fields',detail=str(exc)))
    return row


def cell_decision(cell_id,cell,rows):
    initial=[r for r in rows if r['replicate'] in (0,1,2)]
    replacement=[r for r in rows if r['replicate']==3]
    first_invalid=sum(not r['valid'] for r in initial)
    initial_failed=any(r['failures'] for r in initial)
    eligible=(len(initial)==3 and first_invalid==1 and not initial_failed)
    if any(r['replicate'] not in (0,1,2,3) for r in rows):raise ValueError('replicate 4 or 5 is never permitted')
    if replacement and not eligible:raise ValueError('replacement requires exactly one initial INVALID and no FAIL')
    if len({r['replicate'] for r in rows})!=len(rows):raise ValueError('duplicate cell repetition')
    failures=[dict(run_id=r['run_id'],**f) for r in rows for f in r['failures']]
    members=[r for r in rows if r['valid'] and 'primary' in r]
    verdict='FAIL' if failures else 'INCONCLUSIVE' if len(members)<3 else 'PASS'
    followup=verdict=='INCONCLUSIVE' and eligible and not replacement
    return dict(cell_id=cell_id,cell=cell,verdict=verdict,passed=verdict=='PASS',
        repetitions=len(members),invalid_runs=[r['run_id'] for r in rows if not r['valid']],
        initial_invalid_count=first_invalid,followup_eligible=followup,
        replacement_replicate=3 if followup else None,final=not followup,failures=failures,
        metrics={name:{kind:statistics.fmean(r['primary']['checks'][name][kind] for r in members)
            if members and all(r['primary']['checks'][name][kind] is not None for r in members) else None
            for kind in ('prototype','simulation')} for name in BANDS})


def gather_records(index,records):
    from .replay import cell_map
    cells=cell_map(index)
    expected={r['run_id']:r for r in index['runs']};seen=set();table=[];fatal=[];secondary=[]
    for result in records:
        rid=result.get('run_id');run=expected.get(rid)
        if run is None or rid in seen:
            fatal.append(dict(run_id=rid,check='unexpected/duplicate repetition'));continue
        seen.add(rid);cell=cells[run['cell_id']]
        mismatches=[dict(run_id=rid,check=key+' mismatch') for key,value in
            (('input_sha256',run['manifest_sha256']),('code_commit',index['code_commit']),
             ('source_run_id',run.get('source_run_id',index['source_run_id'])),('cell_id',run['cell_id']),('replicate',run['replicate']))
            if result.get(key)!=value]
        if cell.get('role')=='secondary':
            row=dict(run_id=rid,cell_id=run['cell_id'],replicate=run['replicate'],role='secondary',
                category=regime_category(result.get('prototype',{}).get('metrics',{}).get('block_tx_cache_hit_rate'),result.get('primary',{}).get('metrics',{}).get('block_tx_cache_hit_rate')),
                prototype_hit=result.get('prototype',{}).get('metrics',{}).get('block_tx_cache_hit_rate'),
                simulation_hit=result.get('primary',{}).get('metrics',{}).get('block_tx_cache_hit_rate'),diagnostic_errors=mismatches)
            for name in ('prototype','primary','held_out'):
                for violation in result.get(name,{}).get('violations',[]):
                    error=dict(run_id=rid,check=name+' invariant',violation=violation)
                    row['diagnostic_errors'].append(error)
                    if name=='prototype':fatal.append(error)
            if result.get('execution_error'):row['diagnostic_errors'].append(dict(check='execution',detail=result['execution_error']))
            secondary.append(row);table.append(row);continue
        fatal.extend(mismatches);table.append(repetition(result))
    for rid in sorted(set(expected)-seen):
        run=expected[rid]
        if cells[run['cell_id']].get('role')=='secondary':
            row=dict(run_id=rid,role='secondary',cell_id=run['cell_id'],replicate=run['replicate'],category='NOT RECORDED',diagnostic_errors=[dict(check='missing repetition')])
            secondary.append(row);table.append(row)
        # Missing primary evidence is not an INVALID guard observation and
        # cannot authorise a follow-up. Fewer than three comparisons is inconclusive.
    aggregates=[]
    for i,cell in cells.items():
        if cell.get('role')=='secondary' or cell['dispatcher_utilisation']>.5:continue
        rows=[r for r in table if r['cell_id']==i and r.get('role')!='secondary']
        aggregates.append(cell_decision(i,cell,rows))
    failures=fatal+[f for a in aggregates for f in a['failures']]
    verdict=('FAIL' if failures else 'INCONCLUSIVE' if not aggregates or any(a['verdict']=='INCONCLUSIVE' for a in aggregates) else 'PASS')
    missing=[dict(run_id=rid,check='missing repetition') for rid in sorted(set(expected)-seen)
             if cells[expected[rid]['cell_id']].get('role')!='secondary']
    return dict(status=STATUS[verdict],verdict=verdict,invalid_runs=[r['run_id'] for r in table if r.get('status')=='INVALID'],
        failures=failures,missing_primary=missing,secondary_regime=secondary,
        per_repetition=sorted(table,key=lambda r:r['run_id']),aggregates=aggregates,
        followup_plan=[dict(cell_id=a['cell_id'],replicate=3,reason='exactly one initial INVALID') for a in aggregates if a['followup_eligible']],
        excluded_cells=index['excluded_cells'],bands=BANDS,source_run_id=index['source_run_id'],code_commit=index['code_commit'],
        source_run_ids=index.get('source_run_ids',[index['source_run_id']]),part_receipts=index.get('part_receipts',[]))
