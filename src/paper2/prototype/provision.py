"""Pinned native source build and conformance; invoked only explicitly on ARM runner."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import time
import urllib.request

from .backends import Signer,Verifier,negative


def command(args,cwd,log,timeout=1800):
    with Path(log).open("ab") as stream:
        stream.write(("\n$ "+" ".join(map(str,args))+"\n").encode());stream.flush()
        subprocess.run(list(map(str,args)),cwd=cwd,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=timeout)


def fetch(pin,root):
    archive=root/(pin["version"]+"-"+pin["sha256"][:12]+".tar.gz")
    urllib.request.urlretrieve(pin["url"],archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=pin["sha256"]:
        raise ValueError("source archive SHA-256 mismatch")
    directory=root/("source-"+pin["sha256"][:12]);directory.mkdir()
    with tarfile.open(archive) as tf:
        # Python 3.13 data filter rejects traversal, links outside the extraction root and devices.
        tf.extractall(directory,filter="data")
    return next(p for p in directory.iterdir() if p.is_dir())


def build(root,artifacts):
    root=Path(root).resolve();root.mkdir(parents=True,exist_ok=True)
    artifacts=Path(artifacts);artifacts.mkdir(parents=True,exist_ok=True)
    pins=json.loads(Path(__file__).with_name("source_pins.json").read_text())
    start=time.monotonic();openssl=fetch(pins["openssl"],root)
    prefix=root/"openssl";log=artifacts/"native-build.log"
    command(["perl","Configure","linux-aarch64","shared","no-legacy","--libdir=lib",f"--prefix={prefix}"],openssl,log)
    command(["make","-j3"],openssl,log)
    command(["make","install_sw"],openssl,log)
    oqs=fetch(pins["liboqs"],root);builddir=root/"liboqs-build";install=root/"liboqs"
    command(["cmake","-S",oqs,"-B",builddir,"-GNinja","-DCMAKE_BUILD_TYPE=Release","-DBUILD_SHARED_LIBS=ON",
        "-DOQS_ENABLE_SIG_STFL_XMSS=ON","-DOQS_ENABLE_SIG_STFL_LMS=OFF",
        "-DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON",
        "-DOQS_MINIMAL_BUILD=SIG_ml_dsa_44",f"-DOPENSSL_ROOT_DIR={prefix}",f"-DCMAKE_INSTALL_PREFIX={install}",
        "-DCMAKE_INSTALL_LIBDIR=lib"],root,log)
    command(["cmake","--build",builddir,"--parallel","3","--target","oqs","kat_sig_stfl"],root,log)
    command(["cmake","--install",builddir],root,log)
    result=dict(openssl_source=str(openssl),liboqs_source=str(oqs),liboqs_build=str(builddir),
        openssl_prefix=str(prefix),liboqs_prefix=str(install),pins=pins,elapsed=time.monotonic()-start)
    (artifacts/"native-build.json").write_bytes(json.dumps(result,indent=2).encode()+b"\n")


def conformance(artifacts):
    artifacts=Path(artifacts);data=json.loads((artifacts/"native-build.json").read_text())
    openssl=Path(data["openssl_source"]);oqs=Path(data["liboqs_source"])
    log=artifacts/"native-conformance.log";records=[]
    kat=oqs/"tests/KATs/sig_stfl/xmss/XMSS-SHA2_10_256.rsp"
    args=[str(Path(data["liboqs_build"])/"tests/kat_sig_stfl"),"XMSS-SHA2_10_256",str(kat)]
    raw=subprocess.check_output(args,cwd=oqs,timeout=600,stderr=subprocess.STDOUT).replace(b"\r\n",b"\n")
    (artifacts/"xmss-kat-output.txt").write_bytes(raw)
    expected=json.loads((oqs/"tests/KATs/sig_stfl/kats.json").read_text())["XMSS-SHA2_10_256"]
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("shipped XMSS KAT digest mismatch")
    records.append(dict(backend="xmss",kind="liboqs shipped XMSS KAT",passed=True,
        vector=str(kat),vector_sha256=hashlib.sha256(kat.read_bytes()).hexdigest(),expected_output_sha256=expected))
    for family,algorithm in (("ml_dsa","ML-DSA-44"),("slh_dsa","SLH-DSA-SHA2-128s")):
        vector=openssl/f"test/recipes/30-test_evp_data/evppkey_{family}_sigver.txt"
        if vector.is_file():
            text=vector.read_text();count=text.count("Verify-Message-Public = "+algorithm+":")
            if "ACVP test data" not in text or not count:raise ValueError("official target ACVP vectors absent/empty")
            command(["perl","util/wrap.pl","test/evp_test","-config","test/default.cnf",vector],openssl,log,900)
            records.append(dict(backend=family,kind="pinned OpenSSL ACVP-derived sigVer file via evp_test",
                vector=str(vector),vector_sha256=hashlib.sha256(vector.read_bytes()).hexdigest(),
                target_algorithm=algorithm,target_cases=count,passed=True))
        else:
            records.append(dict(backend=family,kind="roundtrip plus negative only; official vectors unavailable",passed=True))
    for backend in ("ed25519","ml_dsa_44","slh_dsa_sha2_128s","xmss"):
        signer=Signer(backend);verifier=Verifier(backend)
        try:
            verifier.register(signer.public_key);message=b"paper2-g3-provider-smoke";signature=signer.sign(message)
            if (not verifier.verify(message,signature,signer.public_key)
                    or verifier.verify(message,negative(signature,"bit_flip",backend),signer.public_key)
                    or verifier.verify(message,negative(signature,"random_bytes",backend),signer.public_key)):
                raise ValueError("provider roundtrip/negative check failed")
            info=verifier.metadata()
            if backend in ("ml_dsa_44","slh_dsa_sha2_128s") and "OpenSSL 3.5.5 " not in info["version"]:
                raise ValueError("wrong libcrypto loaded")
            if backend=="xmss" and info["version"]!="0.16.0":raise ValueError("wrong liboqs loaded")
            records.append(dict(backend=backend,kind="roundtrip plus two correct-length negatives",metadata=info,passed=True))
        finally:signer.close();verifier.close()
    (artifacts/"conformance.json").write_bytes(json.dumps(records,indent=2).encode()+b"\n")


def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True);p.add_argument("--artifacts",type=Path,required=True)
    p.add_argument("--stage",choices=("build","conformance"),required=True);p.add_argument("--execute",action="store_true")
    args=p.parse_args()
    if not args.execute or os.environ.get("GITHUB_ACTIONS")!="true" or platform.machine().lower() not in ("aarch64","arm64"):
        raise SystemExit("explicit --execute on the ARM GitHub runner is required")
    if args.stage=="build":build(args.root,args.artifacts)
    else:conformance(args.artifacts)


if __name__=="__main__":main()
