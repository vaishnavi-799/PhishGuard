"""String-similarity algorithms implemented from scratch (no dependencies). All similarity values are in [0, 1]."""
from __future__ import annotations

from collections import Counter


def levenshtein(a: str, b: str) -> int:
    """Minimum number of single-character insertions, deletions or substitutions turning a into b."""
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def levenshtein_similarity(a: str, b: str) -> float:
    m = max(len(a), len(b))
    return 1.0 if m == 0 else 1.0 - levenshtein(a, b) / m


def jaro(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    window = max(max(len(a), len(b)) // 2 - 1, 0)
    ma, mb = [False] * len(a), [False] * len(b)
    matches = 0
    for i, ca in enumerate(a):
        for j in range(max(0, i - window), min(len(b), i + window + 1)):
            if not mb[j] and b[j] == ca:
                ma[i] = mb[j] = True
                matches += 1
                break
    if matches == 0:
        return 0.0
    t, k = 0, 0
    for i in range(len(a)):
        if ma[i]:
            while not mb[k]:
                k += 1
            t += a[i] != b[k]
            k += 1
    t //= 2
    return (matches / len(a) + matches / len(b) + (matches - t) / matches) / 3


def jaro_winkler(a: str, b: str, p: float = 0.1, max_prefix: int = 4) -> float:
    j = jaro(a, b)
    prefix = 0
    for ca, cb in zip(a[:max_prefix], b[:max_prefix]):
        if ca != cb:
            break
        prefix += 1
    return j + prefix * p * (1 - j)


def ngrams(s: str, n: int = 2) -> Counter:
    if len(s) < n:
        return Counter([s]) if s else Counter()
    return Counter(s[i:i + n] for i in range(len(s) - n + 1))


def ngram_similarity(a: str, b: str, n: int = 2) -> float:
    """Sorensen-Dice coefficient over character n-gram multisets."""
    ga, gb = ngrams(a, n), ngrams(b, n)
    total = sum(ga.values()) + sum(gb.values())
    if total == 0:
        return 1.0 if a == b else 0.0
    return 2 * sum((ga & gb).values()) / total
