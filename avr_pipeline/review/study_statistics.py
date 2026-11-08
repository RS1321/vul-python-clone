"""Dependency-free paired statistics; incomplete outcomes are never counted as failures."""
import math
import random
from statistics import NormalDist


def wilson(successes, total, confidence=0.95):
    if not total:
        return None
    z = NormalDist().inv_cdf((1 + confidence) / 2)
    p = successes / total
    scale = 1 + z*z/total
    center = (p + z*z/(2*total))/scale
    half = z*math.sqrt(p*(1-p)/total + z*z/(4*total*total))/scale
    return [max(0, center-half), min(1, center+half)]


def paired(a, b):
    pairs = [(a[k], b[k]) for k in sorted(a.keys() & b.keys()) if type(a[k]) is bool and type(b[k]) is bool]
    n = len(pairs)
    if not n:
        return {'n': 0, 'mcnemar_exact_p': None, 'risk_difference': None, 'matched_odds_ratio': None}
    wins = sum(x and not y for x, y in pairs)
    losses = sum(y and not x for x, y in pairs)
    discordant = wins + losses
    # Exact two-sided conditional binomial test. log-sum avoids huge integer conversion.
    if discordant:
        terms = [math.lgamma(discordant+1)-math.lgamma(i+1)-math.lgamma(discordant-i+1)-discordant*math.log(2)
                 for i in range(min(wins, losses)+1)]
        p = min(1.0, 2*sum(math.exp(t) for t in terms))
    else:
        p = 1.0
    return {'n': n, 'a_only': wins, 'b_only': losses, 'both': sum(x and y for x, y in pairs),
            'neither': sum(not x and not y for x, y in pairs), 'mcnemar_exact_p': p,
            'risk_difference': (wins-losses)/n,
            'matched_odds_ratio': wins/losses if losses else None,
            'odds_ratio_boundary': 'infinite' if wins and not losses else 'undefined' if not discordant else None,
            'a_rate_ci95': wilson(sum(x for x, y in pairs), n),
            'b_rate_ci95': wilson(sum(y for x, y in pairs), n)}


def repeated_cluster_ci(repetitions, samples=4000, seed=1729):
    """Resample whole matched repetitions, not repeated findings as independent samples."""
    if len(repetitions) < 3:
        return None
    rng = random.Random(seed)
    effects = sorted(sum(rng.choice(repetitions) for _ in repetitions)/len(repetitions) for _ in range(samples))
    return [effects[int(.025*(samples-1))], effects[int(.975*(samples-1))]]


def holm(pvalues):
    ordered = sorted((p, i) for i, p in enumerate(pvalues) if p is not None)
    adjusted = [None]*len(pvalues)
    previous = 0
    for rank, (p, i) in enumerate(ordered):
        previous = max(previous, min(1, (len(ordered)-rank)*p))
        adjusted[i] = previous
    return adjusted
