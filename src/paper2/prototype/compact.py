"""Compact public evidence; exactly the authorised raw-byte checks run on ARM."""
import base64
import hashlib
import json
import struct
from . import corpus
from src.blockchain.block import Block

FORMAT="paper2-compact-public-corpus-v2"
CTX=tuple(corpus.CONTEXT)
def sha(b):return hashlib.sha256(b).hexdigest()
def fold(leaves):
    level=list(leaves)
    if not level:return sha(b"")
    while len(level)>1:
        if len(level)%2:level.append(level[-1])
        level=[sha((level[i]+level[i+1]).encode()) for i in range(0,len(level),2)]
    return level[0]


def audit_full(doc,full_path=None):
    """Fail before upload, binding every source signature/leaf/root to metadata."""
    if set(doc['transactions'])!=set(doc['workload']['transactions']):
        raise ValueError('full corpus transaction coverage mismatch')
    corpus.validate(doc)
    leaves={};transactions=doc["workload"]["transactions"]
    for identity,e in doc["transactions"].items():
        tx=transactions[identity];signature=bytes.fromhex(e["signature_hex"])
        if sha(signature)!=tx["signature_id"]:raise ValueError("signature_id mismatch: "+identity)
        leaf=sha(b"PQ_BLOCKCHAIN_SIM_TX_MERKLE_V1"+corpus.frozen_tx(tx,signature).serialize())
        if e.get("wire_leaf_hash")!=leaf:raise ValueError("Merkle leaf mismatch: "+identity)
        leaves[identity]=leaf
    roots={}
    for b in doc["workload"]["blocks"]:
        bid=b["block_id"];root=fold(leaves[t] for t in b["tx_ids"])
        if doc["block_objects"][bid].get("merkle_root")!=root:raise ValueError("Merkle root mismatch: "+bid)
        roots[bid]=root
    if full_path is None:
        raw=corpus.canonical(doc)+b"\n";digest=sha(raw);size=len(raw)
    else:
        from src.paper2.model.service_times import sha256_file
        from pathlib import Path
        path=Path(full_path);digest=sha256_file(path);size=path.stat().st_size
    return dict(schema="paper2-arm-compact-audit-v1",cache_key_version=corpus.KEY_VERSION,
        signature_ids_checked=len(transactions),wire_leaves_checked=len(leaves),block_roots_checked=len(roots),
        full_corpus_sha256=digest,full_corpus_bytes=size,passed=True,
        moved_checks=["signature_id derivation","signature-bearing transaction-wire Merkle leaf/root recomputation"])


def document(doc,receipt):
    if not receipt.get("passed"):raise ValueError("successful ARM audit required")
    txs=doc["workload"]["transactions"];columns=sorted(set().union(*(set(t) for t in txs.values()))-set(CTX)-{"public_key_id","tx_id"})
    from .public_corpus import audit
    audit(txs)
    keys={};rows={}
    def key(e):
        public=bytes.fromhex(e["public_key_hex"]);kid=sha(public)
        if kid!=e["key_id"]:raise ValueError("public key identifier mismatch")
        keys[kid]=public;return kid
    for identity,tx in txs.items():
        e=doc["transactions"][identity];kid=key(e)
        if kid!=tx["public_key_id"]:raise ValueError("transaction public key identifier mismatch")
        rows[identity]=[sum(1<<i for i,c in enumerate(columns) if c in tx)]+[tx.get(c) for c in columns]+[kid,bytes.fromhex(e["payload_hex"]),
            len(bytes.fromhex(e["signature_hex"])),e["wire_leaf_hash"],e.get("leaf_index")]
    blocks={}
    for bid,e in doc["blocks"].items():
        blocks[bid]=dict(payload=bytes.fromhex(e["payload_hex"]),key_id=key(e),
            signature_id=sha(bytes.fromhex(e["signature_hex"])),signature_size=len(bytes.fromhex(e["signature_hex"])))
    return dict(version=FORMAT,backend=doc["backend"],context=doc["context"],cache_key_version=corpus.KEY_VERSION,
        columns=columns,public_keys=keys,transactions=rows,blocks=blocks,block_objects=doc["block_objects"],
        block_specs=doc["workload"]["blocks"],arm_audit=receipt)


def expand(doc):
    """Decode columns without inventing signatures; hashes are audit commitments."""
    if doc.get("version")!=FORMAT:return doc
    if doc.get("cache_key_version")!=corpus.KEY_VERSION:raise ValueError("compact key version mismatch")
    from .public_corpus import audit
    audit({column:None for column in doc['columns']})
    result=dict(version=FORMAT+"-expanded",backend=doc["backend"],context=doc["context"],cache_key_version=corpus.KEY_VERSION,
        block_objects=doc["block_objects"],blocks={},transactions={},workload=dict(transactions={},blocks=doc["block_specs"]),arm_audit=doc["arm_audit"])
    receipt=doc["arm_audit"]
    if (not receipt.get("passed") or receipt.get("signature_ids_checked")!=len(doc["transactions"]) or
        receipt.get("wire_leaves_checked")!=len(doc["transactions"]) or receipt.get("block_roots_checked")!=len(doc["block_specs"])):
        raise ValueError("compact ARM audit count mismatch")
    keys=doc["public_keys"]
    if any(sha(public)!=kid for kid,public in keys.items()):raise ValueError("compact public key hash mismatch")
    for identity,row in doc["transactions"].items():
        n=len(doc["columns"])
        if len(row)!=n+6:raise ValueError("compact transaction column mismatch")
        kid,payload,size,leaf,index=row[n+1:];tx={c:row[i+1] for i,c in enumerate(doc["columns"]) if row[0]>>i&1};tx.update(doc["context"],tx_id=identity,public_key_id=kid)
        if isinstance(size,bool) or not isinstance(size,int) or not 0<=size<=1_000_000:raise ValueError("compact signature size invalid")
        if not isinstance(leaf,str) or len(leaf)!=64 or any(c not in '0123456789abcdef' for c in leaf):raise ValueError("compact leaf hash invalid")
        entry=dict(payload_hex=payload.hex(),public_key_hex=keys[kid].hex(),key_id=kid,
            signature_size=size,wire_leaf_hash=leaf,leaf_index=index,key_version=corpus.KEY_VERSION)
        entry["cache_key"]=corpus.cache_key_v2(doc["context"],kid,bytes.fromhex(entry["payload_hex"]),tx["nonce"],tx["signature_id"])
        result["transactions"][identity]=entry;result["workload"]["transactions"][identity]=tx
    for bid,e in doc["blocks"].items():
        result["blocks"][bid]=dict(payload_hex=e["payload"].hex(),
            public_key_hex=keys[e["key_id"]].hex(),key_id=e["key_id"],signature_size=e["signature_size"],signature_id=e["signature_id"])
    return result


def pack(value):
    """Versioned lossless TLV: raw bytes/digests, varint lengths, no pickle.

    N/T/F=null/bools; I=zigzag integer; D=IEEE754 binary64; H=32-byte
    lowercase hex string; S=UTF8; B=bytes; L=list; M=ordered string-key map.
    Counts/lengths and zigzag integers use unsigned base-128 varints.
    """
    result=bytearray(b'P2COMPACT2\x00')
    def integer(n):
        while n>=128:result.append((n&127)|128);n>>=7
        result.append(n)
    def write(v):
        if v is None:result.extend(b'N')
        elif isinstance(v,bool):result.extend(b'T' if v else b'F')
        elif isinstance(v,int):result.extend(b'I');integer(v*2 if v>=0 else -v*2-1)
        elif isinstance(v,float):result.extend(b'D');result.extend(struct.pack('>d',v))
        elif isinstance(v,bytes):result.extend(b'B');integer(len(v));result.extend(v)
        elif isinstance(v,str):
            if len(v)==64 and all(c in '0123456789abcdef' for c in v):result.extend(b'H');result.extend(bytes.fromhex(v))
            else:
                raw=v.encode();result.extend(b'S');integer(len(raw));result.extend(raw)
        elif isinstance(v,list):
            result.extend(b'L');integer(len(v))
            for item in v:write(item)
        elif isinstance(v,dict):
            result.extend(b'M');integer(len(v))
            for key in sorted(v):write(key);write(v[key])
        else:raise ValueError('unsupported compact value')
    write(value);return bytes(result)


def unpack(raw):
    if not raw.startswith(b'P2COMPACT2\x00'):raise ValueError('compact binary magic mismatch')
    view=memoryview(raw);at=11
    def take(n):
        nonlocal at
        if at+n>len(view):raise ValueError('truncated compact record')
        v=view[at:at+n];at+=n;return v
    def integer():
        n=shift=0
        while True:
            b=take(1)[0];n|=(b&127)<<shift
            if not b&128:return n
            shift+=7
            if shift>128:raise ValueError('compact integer too large')
    def read(depth=0):
        if depth>64:raise ValueError('compact nesting too deep')
        tag=bytes(take(1))
        if tag==b'N':return None
        if tag in (b'T',b'F'):return tag==b'T'
        if tag==b'I':
            n=integer();return -(n//2)-1 if n&1 else n//2
        if tag==b'D':return struct.unpack('>d',take(8))[0]
        if tag==b'H':return bytes(take(32)).hex()
        if tag in (b'S',b'B'):
            b=bytes(take(integer()));return b.decode() if tag==b'S' else b
        if tag==b'L':return [read(depth+1) for _ in range(integer())]
        if tag==b'M':
            result={};n=integer()
            for _ in range(n):
                k=read(depth+1)
                if not isinstance(k,str) or k in result:raise ValueError('invalid compact map key')
                result[k]=read(depth+1)
            return result
        raise ValueError('unknown compact tag')
    value=read()
    if at!=len(raw):raise ValueError('trailing compact bytes')
    return value
