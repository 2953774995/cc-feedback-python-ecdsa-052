"""
Batch verification and algorithm-strength auditing of ECDSA signatures.

This module is a companion to the regular :class:`~ecdsa.keys.VerifyingKey`
API: it verifies many ``(public key, message, signature, hash)`` records in
one go and classifies the result of each record instead of raising on bad
input. Malformed records are reported individually and never abort the
batch.

The primary entry point is :func:`audit_signatures`.
"""
import binascii
import hashlib
from collections import namedtuple

from ._compat import bit_length
from .keys import VerifyingKey


__all__ = ["AuditResult", "audit_signatures", "DEFAULT_ALLOWED_HASHES"]


#: Hash algorithms accepted when ``allowed_hashes`` is not provided.
DEFAULT_ALLOWED_HASHES = ["sha256", "sha384", "sha512"]

#: Hash algorithms the auditor knows how to use for verification.
_KNOWN_HASHES = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

# Result of a batch audit. ``items`` is a list of per-record dicts, ``stats``
# is a dict with the aggregate counters.
AuditResult = namedtuple("AuditResult", ["items", "stats"])


def _empty_stats():
    return {"ok": 0, "bad": 0, "by_reason": {}}


def _record_item(index, reason, curve=None, curve_bits=None, hash_name=None,
                 issues=None):
    return {
        "index": index,
        "ok": reason == "ok",
        "reason": reason,
        "curve": curve,
        "curve_bits": curve_bits,
        "hash": hash_name,
        "issues": issues if issues is not None else [],
    }


def _decode_hex(value):
    """Decode a hexadecimal string into bytes.

    Raises :class:`ValueError` for anything that is not a valid hex string.
    """
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeError:
            raise ValueError("signature is not ASCII hexadecimal")
    else:
        raise ValueError("signature must be a hexadecimal string")
    try:
        return binascii.unhexlify(raw)
    except (binascii.Error, TypeError, ValueError):
        raise ValueError("signature is not valid hexadecimal")


def _decode_message(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ValueError("message must be a string")


def _pem_text(value):
    """Return the PEM text of a record, rejecting non-string values."""
    if isinstance(value, bytes):
        try:
            return value.decode("ascii")
        except UnicodeError:
            raise ValueError("public key is not ASCII PEM text")
    if isinstance(value, str):
        return value
    raise ValueError("public key must be PEM text")


def _normalise_allowed(allowed_hashes):
    if allowed_hashes is None:
        allowed = DEFAULT_ALLOWED_HASHES
    else:
        allowed = allowed_hashes
    if isinstance(allowed, str):
        allowed = [allowed]
    normalised = set()
    for name in allowed:
        if isinstance(name, bytes):
            name = name.decode("ascii", "replace")
        normalised.add(str(name).strip().lower())
    return normalised


def _hash_name(record):
    value = record.get("hash")
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    if not isinstance(value, str):
        raise ValueError("hash field must be a string")
    name = value.strip().lower()
    if not name:
        raise ValueError("hash field is empty")
    return name


def audit_signatures(records, min_curve_bits=224, allowed_hashes=None):
    """Verify and audit a batch of ECDSA signature records.

    Each record is a dict with the following fields:

    ``public_key``
        PEM-encoded public key (``BEGIN PUBLIC KEY``).
    ``message``
        The signed message, as text.
    ``signature``
        The raw signature in hexadecimal encoding.
    ``hash``
        One of ``sha1``, ``sha256``, ``sha384`` or ``sha512``.

    A record that is structurally broken (bad PEM, non-hexadecimal
    signature, missing fields, unknown hash) yields ``malformed`` and does
    not stop processing of the remaining records.

    :param records: sequence of records to audit
    :param int min_curve_bits: smallest acceptable curve size in bits;
        records on smaller curves are reported as ``weak_curve``
    :param allowed_hashes: hash names considered acceptable; defaults to
        ``["sha256", "sha384", "sha512"]``. Records using any other known
        hash are reported as ``weak_hash``.

    :return: :class:`AuditResult` with ``items`` (per-record results) and
        ``stats`` (``ok``, ``bad`` and ``by_reason`` counters)
    :rtype: AuditResult
    """
    allowed = _normalise_allowed(allowed_hashes)

    items = []
    stats = _empty_stats()
    # Parsing a PEM key is comparatively expensive and batches frequently
    # repeat the same key, so cache the parsed verifying keys per call.
    key_cache = {}

    for index, record in enumerate(records):
        item = _audit_one(index, record, min_curve_bits, allowed, key_cache)
        items.append(item)

        if item["ok"]:
            stats["ok"] += 1
        else:
            stats["bad"] += 1
            reason = item["reason"]
            stats["by_reason"][reason] = stats["by_reason"].get(reason, 0) + 1

    return AuditResult(items=items, stats=stats)


def _audit_one(index, record, min_curve_bits, allowed, key_cache):
    if not isinstance(record, dict):
        return _record_item(
            index, "malformed", issues=["record is not a mapping"]
        )

    hash_name = None
    try:
        hash_name = _hash_name(record)
    except ValueError:
        pass

    # Structural parsing: any failure here is "malformed".
    try:
        if hash_name is None:
            raise ValueError("hash field must be a string")
        pem = _pem_text(record.get("public_key"))
        message = _decode_message(record.get("message"))
        signature = _decode_hex(record.get("signature"))
        hashfunc = _KNOWN_HASHES.get(hash_name)
        if hashfunc is None:
            raise ValueError(
                "unsupported hash algorithm %r" % (hash_name,)
            )
        verifying_key = key_cache.get(pem)
        if verifying_key is None:
            verifying_key = VerifyingKey.from_pem(pem)
            key_cache[pem] = verifying_key
    except Exception as exc:
        return _record_item(
            index,
            "malformed",
            hash_name=hash_name,
            issues=["malformed record: %s" % (exc,)]
            if str(exc) else ["malformed record"],
        )

    curve = verifying_key.curve.name
    curve_bits = bit_length(verifying_key.curve.order)

    issues = []
    reason = "ok"

    if min_curve_bits is not None and curve_bits < min_curve_bits:
        reason = "weak_curve"
        issues.append(
            "curve %s is %d bits, below the required %d bits"
            % (curve, curve_bits, min_curve_bits)
        )

    if hash_name not in allowed:
        if reason == "ok":
            reason = "weak_hash"
        issues.append(
            "hash %s is not allowed (allowed: %s)"
            % (hash_name, ", ".join(sorted(allowed)) or "none")
        )

    try:
        verifying_key.verify(signature, message, hashfunc=hashfunc)
    except Exception as exc:
        if reason == "ok":
            reason = "invalid_signature"
        issues.append("signature verification failed: %s" % (exc,))

    return _record_item(
        index,
        reason,
        curve=curve,
        curve_bits=curve_bits,
        hash_name=hash_name,
        issues=issues,
    )
