"""
Single source of truth mapping a numeric severity score to its label
(LLD §6: "never let these two drift out of sync"). Every rule computes a
score; only this function decides what label that score displays as.
"""


def severity_label_for(score: int) -> str:
    if score >= 86:
        return "critical"
    if score >= 61:
        return "high"
    if score >= 31:
        return "medium"
    return "low"