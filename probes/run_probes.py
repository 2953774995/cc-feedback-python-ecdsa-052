#!/usr/bin/env python3
"""验收探针：ECDSA 签名批量校验与算法强度审计（6 条契约）。密钥与签名现场生成。"""
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def api():
    from ecdsa.audit import audit_signatures
    return audit_signatures

def signed(curve_name="NIST256p", hash_name="sha256", message="payload-1"):
    from ecdsa import SigningKey, NIST256p, NIST192p
    curve = {"NIST256p": NIST256p, "NIST192p": NIST192p}[curve_name]
    sk = SigningKey.generate(curve=curve)
    msg = message.encode()
    sig = sk.sign_deterministic(msg, hashfunc=getattr(__import__("hashlib"), hash_name))
    return {"public_key": sk.get_verifying_key().to_pem().decode(),
            "message": message, "signature": sig.hex(), "hash": hash_name}

@probe("P01 批量入口与合规签名")
def p01():
    fn = api(); out = fn([signed()], min_curve_bits=224)
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for f in ("index", "ok", "reason", "curve", "curve_bits", "hash", "issues"):
        assert f in item, f"item 缺字段 {f}"
    assert item["ok"] and item["reason"] == "ok", f"合规签名应 ok，实际 {item['reason']}"
    assert item["curve_bits"] >= 224 and item["hash"] == "sha256"

@probe("P02 弱曲线")
def p02():
    fn = api(); item = fn([signed(curve_name="NIST192p")], min_curve_bits=224).items[0]
    assert item["reason"] == "weak_curve", f"应为 weak_curve，实际 {item['reason']}"
    assert item["ok"] is False and item["curve_bits"] == 192

@probe("P03 弱哈希")
def p03():
    fn = api(); item = fn([signed(hash_name="sha1")], min_curve_bits=224).items[0]
    assert item["reason"] == "weak_hash", f"应为 weak_hash，实际 {item['reason']}"

@probe("P04 签名无效")
def p04():
    fn = api(); rec = signed(); other = signed(message="payload-2")
    rec["signature"] = other["signature"]
    out = fn([rec, signed()], min_curve_bits=224)
    assert out.items[0]["reason"] == "invalid_signature", f"应为 invalid_signature，实际 {out.items[0]['reason']}"
    assert out.items[1]["ok"], "坏签名之后应继续"

@probe("P05 结构损坏")
def p05():
    fn = api(); rec = signed(); rec["signature"] = "zz"
    bad_pem = signed(); bad_pem["public_key"] = "-----BEGIN PUBLIC KEY-----\nxx\n-----END PUBLIC KEY-----"
    out = fn([rec, bad_pem], min_curve_bits=224)
    assert out.items[0]["reason"] == "malformed", f"应为 malformed，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "malformed", f"坏 PEM 应 malformed，实际 {out.items[1]['reason']}"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = api(); rec = signed()
    out = fn([rec, signed(curve_name="NIST192p"), "garbage"], min_curve_bits=224)
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("weak_curve") == 1 and st["by_reason"].get("malformed") == 1, st["by_reason"]
    empty = fn([]); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    recs = [rec] * 200
    t0 = time.perf_counter(); out2 = fn(recs, min_curve_bits=224); cost = time.perf_counter() - t0
    assert len(out2.items) == 200 and cost < 3.0, f"200 条耗时 {cost:.2f}s 超过 3s"

def main():
    print("=" * 60); print("验收探针：ECDSA 签名批量校验与算法强度审计（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
