from __future__ import annotations


def score_action(progress_gain: float, cumulative_cost: float, risk_penalty: float, hallucination_flag: bool) -> float:
    score = progress_gain * 100.0 - cumulative_cost - risk_penalty * 5.0
    if hallucination_flag:
        score -= 1_000_000.0
    return score
