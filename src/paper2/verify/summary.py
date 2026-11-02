"""Independent full-artifact recomputation; does not import the online collector."""

import csv
import json
import math
from pathlib import Path


def recompute(events_csv, jobs_csv, config):
    classes=("admission","block_tx","block_sig");queues=(*classes,"block")
    spec=config.get("summary",{});edges=spec.get("histogram_edges",[0,.00001,.0001,.001,.01,.1,1,10])
    width=spec.get("window_width",1);window=spec.get("analysis_window")
    waiting={c:dict(count=0,sum=0.0,sum_squares=0.0,histogram=[0]*len(edges)) for c in classes}
    busy=dict.fromkeys(classes,0.0);cohort={c:dict(enqueued=0,count=0,wait_sum=0.0) for c in classes}
    with Path(jobs_csv).open(newline="",encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            j=json.loads(row["record"])
            if j["status"]!="end":continue
            cls=j["job_class"];w=j["start_t"]-j["enqueue_t"];v=waiting[cls]
            v["count"]+=1;v["sum"]+=w;v["sum_squares"]+=w*w
            index=sum(w>=edge for edge in edges)-1;v["histogram"][index]+=1
            busy[cls]+=j["end_t"]-j["start_t"]
            if window and window[0]<=j["enqueue_t"]<=window[1]:
                cohort[cls]["count"]+=1;cohort[cls]["wait_sum"]+=w
    area=dict.fromkeys(queues,0.0);maximum=dict.fromkeys(queues,0);clip=dict.fromkeys(queues,0.0)
    bounds={"start":None,"end":None};samples=[];n_sample=0;last=0.0;q=dict.fromkeys(queues,0)
    pending={};direct={};blocks={};drops={};cache={};pool={};dispatch=accepted=events=0
    sizes={b["block_id"]:len(b["tx_ids"]) for b in config.get("blocks",[])}
    with Path(events_csv).open(newline="",encoding="utf-8") as stream:
        for r in csv.DictReader(stream):
            t=float(r["t"]);event=r["event"];jid=r["job_id"];cls=r["job_class"]
            for c in queues:area[c]+=(t-last)*q[c]
            if window:
                overlap=max(0,min(t,window[1])-max(last,window[0]))
                for c in queues:clip[c]+=overlap*q[c]
                for label,bound in zip(("start","end"),window):
                    if last<=bound<t and bounds[label] is None:bounds[label]=dict(q)
            while n_sample*width<t:
                samples.append(dict(t=n_sample*width,queues=dict(q)));n_sample+=1
            new_total=int(r["q_admission"])+int(r["q_block"])
            if event=="enqueue":
                (pending if new_total>len(pending) else direct)[jid]=cls
            if event=="coalesce_promote" and jid in pending:pending[jid]=cls
            if event=="dispatch":
                dispatch+=1
                if r["chosen_job_id"]:
                    pending.pop(r["chosen_job_id"],None);direct.pop(r["chosen_job_id"],None)
                    pending.update(direct);direct.clear()
            if event=="start":pending.pop(jid,None)
            q={c:sum(v==c for v in pending.values()) for c in classes}
            q["block"]=int(r["q_block"])
            if q["admission"]!=int(r["q_admission"]) or q["block_tx"]+q["block_sig"]!=q["block"]:
                raise ValueError("independent class counter replay mismatch at seq "+r["seq"])
            for c in queues:maximum[c]=max(maximum[c],q[c])
            if samples and samples[-1]["t"]==t:samples[-1]["queues"]=dict(q)
            if n_sample*width==t:samples.append(dict(t=t,queues=dict(q)));n_sample+=1
            if window:
                for label,bound in zip(("start","end"),window):
                    if t==bound:bounds[label]=dict(q)
                if event=="enqueue" and window[0]<=t<=window[1]:cohort[cls]["enqueued"]+=1
            if event in ("drop","dup_drop","struct_reject","state_reject","neg_hit"):
                key=event+":"+r["detail"];drops[key]=drops.get(key,0)+1
            if event.startswith("cache_") or event=="neg_hit":cache[event]=cache.get(event,0)+1
            if event.startswith("pool_"):pool[event]=pool.get(event,0)+1
            if event in ("block_accept","block_reject"):
                bid=r["block_id"];blocks[bid]=dict(delay=t-float(r["arrival_t"]),
                    deadline_missed=t>float(r["deadline_t"]),accepted=event=="block_accept")
                if event=="block_accept":accepted+=sizes[bid]
            last=t;events+=1
    if window:
        for c in queues:clip[c]+=max(0,window[1]-max(last,window[0]))*q[c]
        for label in bounds:
            if bounds[label] is None:bounds[label]=dict(q)
    return dict(schema_version="paper2-summary-v1",histogram_edges=edges,window_width=width,
        end_t=last,event_count=events,waiting=waiting,busy_time=busy,blocks=blocks,
        accepted_valid_tx_count=accepted,drops=drops,cache_counters=cache,pool_counters=pool,
        dispatch_count=dispatch,queue_integrals=area,queue_maxima=maximum,queue_samples=samples,
        analysis=dict(window=window,queue_integrals=clip,queue_boundaries=bounds,classes=cohort))


def differences(actual, expected, path="summary"):
    """Exact structure/counts; sums have <=1e-12 relative error, no absolute slack."""
    if isinstance(expected,dict):
        if not isinstance(actual,dict) or set(actual)!=set(expected):return [path+": keys"]
        return [v for key in expected for v in differences(actual[key],expected[key],path+"."+key)]
    if isinstance(expected,list):
        if not isinstance(actual,list) or len(actual)!=len(expected):return [path+": length"]
        return [v for i,(a,b) in enumerate(zip(actual,expected)) for v in differences(a,b,f"{path}[{i}]")]
    if isinstance(expected,float):
        return [] if math.isclose(actual,expected,rel_tol=1e-12,abs_tol=0) else [path+": sum"]
    return [] if actual==expected else [path+": value"]
