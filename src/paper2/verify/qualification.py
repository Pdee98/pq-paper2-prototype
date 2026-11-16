"""Fail-closed, receipt-only remote model qualification orchestration."""
import argparse,hashlib,json,os,platform,signal,subprocess,sys,threading,time
from pathlib import Path
from .qualification_scale import scale
from .qualification_regression import run as regression
from .qualification_export import unpack_reference,verify

def save(path,value):Path(path).write_text(json.dumps(value,indent=2),encoding='utf-8')

def host():
    cpu='NOT RECORDED';memory=None
    if Path('/proc/cpuinfo').is_file():
        cpu=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),cpu)
        memory=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
    return dict(runner_label=os.environ.get('PAPER2_RUNNER_LABEL','LOCAL-SMOKE'),cpu_model=cpu,total_ram_bytes=memory,
        os=platform.platform(),image_os=os.environ.get('ImageOS','NOT RECORDED'),image_version=os.environ.get('ImageVersion','NOT RECORDED'),
        python=sys.version,code_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        tree_clean=not bool(subprocess.check_output(['git','status','--porcelain']).strip()))

def stage(name,work,receipts,smoke=False):
    work=Path(work);receipts=Path(receipts);work.mkdir(parents=True,exist_ok=True);receipts.mkdir(parents=True,exist_ok=True)
    if name=='scale':return scale(work,receipts,count=32 if smoke else 117292,smoke=smoke)
    if name=='phase-c':return regression(unpack_reference(Path.cwd(),work/'reference'),work,receipts,smoke=smoke)
    if name=='de-capture':
        from .qualification_capture import scale as capture_scale
        return capture_scale(work,receipts,count=12 if smoke else 117292,smoke=smoke)
    if smoke:raise ValueError('G2 has no shortened qualification path')
    target=receipts/'g2.json'
    subprocess.run([sys.executable,'-B','-m','src.paper2.verify.gate4b','--summary',str(target.resolve())],check=True)
    result=json.loads(target.read_text())
    if result['status']!='passed':raise RuntimeError('registered G2 failed or stopped: '+result['status'])
    return result

def proc_group(group):
    """Linux process-group RSS/CPU including workers; no external monitoring dependency."""
    rows={};ticks=os.sysconf('SC_CLK_TCK')
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:
            fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
            if int(fields[2])!=group:continue
            rss=int(next(line.split()[1] for line in (entry/'status').read_text().splitlines() if line.startswith('VmRSS:')))*1024
            rows[int(entry.name)]=(rss,(int(fields[11])+int(fields[12]))/ticks)
        except (OSError,ValueError,StopIteration,IndexError):continue
    return rows

def monitor(name,work,receipts,smoke=False):
    if sys.platform!='linux':raise RuntimeError('remote monitor requires Linux; use child --smoke locally')
    work=Path(work).resolve();receipts=Path(receipts).resolve();work.mkdir(parents=True,exist_ok=True);receipts.mkdir(parents=True,exist_ok=True)
    verify(Path.cwd());save(receipts/'host.json',host())
    command=['/usr/bin/time','-v','-o',str(receipts/'time-v.txt'),sys.executable,'-B','-m',__name__ if __name__!='__main__' else 'src.paper2.verify.qualification',
        'child',name,'--work',str(work),'--receipts',str(receipts)]+(['--smoke'] if smoke else [])
    begin=time.monotonic();peak=0;cpu={};samples=0;reason=None;wall_limit={'scale':6900,'phase-c':10500,'g2':6900,'de-capture':6900}[name]
    with (work/'stage.log').open('wb') as log:
        p=subprocess.Popen(command,start_new_session=True,stdout=log,stderr=subprocess.STDOUT)
        while p.poll() is None:
            values=proc_group(p.pid);peak=max(peak,sum(r[0] for r in values.values()));samples+=1
            for pid,(_,seconds) in values.items():cpu[pid]=max(cpu.get(pid,0),seconds)
            if time.monotonic()-begin>wall_limit:reason='wall watchdog'
            if name=='g2' and sum(cpu.values())>5400:reason='90 CPU-minute watchdog'
            if name=='de-capture':
                available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
                if any(rss>12*1024**3 for rss,_ in values.values()) or available<2*1024**3:reason='capture scale memory guard'
            if reason:os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=15);break
            if samples%30==1:print(json.dumps(dict(stage=name,wall_seconds=time.monotonic()-begin,peak_group_rss_bytes=peak,cpu_seconds_sampled=sum(cpu.values()))),flush=True)
            time.sleep(1)
        code=p.wait()
    result=dict(stage=name,status='passed' if code==0 and not reason else 'failed',returncode=code,watchdog=reason,
        wall_seconds=time.monotonic()-begin,sampled_cpu_seconds=sum(cpu.values()),sampled_peak_group_rss_bytes=peak,
        sampling_period_seconds=1,samples=samples,rss_definition='sum of live process RSS; shared pages may be counted more than once',
        cpu_definition='sum of per-PID maximum sampled user+system CPU; time-v.txt is the authoritative child-tree resource receipt')
    save(receipts/'step.json',result)
    # Receipts only. Raw events, jobs, model input and profile binary remain scratch.
    with (work/'stage.log').open('rb') as f:
        f.seek(max(0,(work/'stage.log').stat().st_size-65536));(receipts/'log-tail.txt').write_bytes(f.read())
    for file in receipts.iterdir():
        if not file.is_file() or file.suffix not in ('.txt','.json') or file.stat().st_size>8*1024**2:raise RuntimeError('non-small receipt refused')
    print(json.dumps(result),flush=True)
    if result['status']!='passed':raise SystemExit(1)

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['monitor','child','verify']);p.add_argument('stage',nargs='?',choices=['scale','phase-c','g2','de-capture'])
    p.add_argument('--work',type=Path);p.add_argument('--receipts',type=Path);p.add_argument('--smoke',action='store_true');a=p.parse_args()
    if a.action=='verify':verify(Path.cwd());return
    if not a.stage or not a.work or not a.receipts:p.error('stage, work and receipts required')
    (monitor if a.action=='monitor' else stage)(a.stage,a.work,a.receipts,a.smoke)

if __name__=='__main__':main()
