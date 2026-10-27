"""Vector primitives for the cross-session memory brain.

Experience (distilled insights) lives in SQLite; this module adds the optional
embedding layer that lets the agent recall *similar* past experience on a new
target whose stack resembles an old one — cross-session transfer that exact
target/category matching cannot do.

Deliberately dependency-free: embeddings come from the gateway's /v1/embeddings
(via LLMClient.embed), vectors are float32 BLOBs in the existing memory DB, and
cosine similarity is pure Python. Callers fall back to lexical matching when
embeddings are unavailable.
"""

from __future__ import annotations

from array import array


def pack_vector(vec: list[float]) -> bytes:
    return array("f", (float(x) for x in vec)).tobytes()


def unpack_vector(blob: bytes, dim: int | None = None) -> list[float]:
    out = array("f")
    out.frombytes(blob)
    vec = out.tolist()
    if dim is not None and len(vec) != dim:
        return vec[:dim] if len(vec) > dim else vec
    return vec


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    return dot / ((na ** 0.5) * (nb ** 0.5))
