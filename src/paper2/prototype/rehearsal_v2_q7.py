"""Pure, pre-dispatch Q7 reader. DIAGNOSTIC, never a G3 evaluator."""
import math

METRICS=('mean_block_delay','mean_admission_wait','p95_block_delay',
         'admission_throughput','deadline_miss_rate')
DISCLOSURE=('One measured repetition per cell; run-to-run variability is not estimated. '
    'Primary and held-out slots are not additional measured repetitions. '
    'Q7 compares two complete models: legacy cycle service with registered legacy '
    'dispatcher treatment versus occupancy service plus explicit dispatcher stages; '
    'both use the same recorded workload and calibration sources/slots.')


def evaluate(records):
    """Signed errors are simulation minus prototype; closure uses magnitudes."""
    errors=[];comparisons=[]
    identities=[(r.get('cell',{}).get('backend'),r.get('cell',{}).get('k')) for r in records]
    if len(records)!=2 or set(identities)!={('xmss',2),('ml_dsa_44',1)}:
        errors.append('missing, duplicate or unexpected cell')
    for record in records:
        cell=record.get('cell',{});prototype=record.get('prototype',{})
        if prototype.get('validity',{}).get('passed') is not True:errors.append('prototype validity failure')
        if prototype.get('violations')!=[]:errors.append('prototype invariant failure or missing verdict')
        if record.get('execution_error'):errors.append('replay execution error')
        for slot in ('primary','held_out'):
            row=dict(backend=cell.get('backend'),k=cell.get('k'),slot=slot,
                     closure=None,passed=False,signed_errors={},admission_errors={})
            try:
                p=prototype['metrics'];old=record['models']['legacy'][slot];new=record['models']['explicit'][slot]
                for mode,value in (('legacy',old),('explicit',new)):
                    if value.get('violations')!=[]:errors.append(mode+' '+slot+' G1 failure or missing verdict')
                    if value['metrics'].get('complete') is not True:errors.append(mode+' '+slot+' incomplete cohort')
                if p.get('complete') is not True:errors.append('prototype incomplete cohort')
                for name in METRICS:
                    values=[m[name] for m in (p,old['metrics'],new['metrics'])]
                    if any(isinstance(v,bool) or not isinstance(v,(int,float)) or not math.isfinite(v) for v in values):
                        raise ValueError('nonfinite or nonnumeric metric')
                    row['signed_errors'][name]=dict(legacy=values[1]-values[0],explicit=values[2]-values[0])
                block=row['signed_errors']['mean_block_delay'];admission=row['signed_errors']['mean_admission_wait']
                baseline=abs(block['legacy'])
                row['closure']=(baseline-abs(block['explicit']))/baseline if baseline>0 else None
                row['admission_errors']=dict(admission,legacy_absolute=abs(admission['legacy']),
                    explicit_absolute=abs(admission['explicit']))
                row['passed']=row['closure'] is not None and row['closure']>=.7 and abs(admission['explicit'])<abs(admission['legacy'])
                row['metrics']=dict(prototype=p,legacy=old['metrics'],explicit=new['metrics'])
            except (KeyError,TypeError,ValueError):errors.append('missing or invalid comparison '+str(cell.get('backend'))+'/'+slot)
            comparisons.append(row)
    verdict='INVALID' if errors else 'SUPPORTED' if len(comparisons)==4 and all(r['passed'] for r in comparisons) else 'NOT SUPPORTED'
    return dict(namespace='paper2-g3-rehearsal-v2',diagnostic=True,excluded_from_G3=True,
        verdict=verdict,comparisons=comparisons,invalid_reasons=errors,disclosure=DISCLOSURE,
        next_action=('author review: run #7 explicit' if verdict=='SUPPORTED' else
                     'author review: run #7 legacy; report latency limitation' if verdict=='NOT SUPPORTED' else
                     'STOP; at most one complete operational rerun on a fresh runner, then stop'))
