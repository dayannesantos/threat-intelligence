def risk_to_score(risk_label: str) -> int:
    mapping = {"Baixo": 25, "Médio": 50, "Alto": 75, "Crítico": 95}
    return mapping.get(risk_label, 0)


def score_to_risk(score: int) -> str:
    if score >= 90:
        return "Crítico"
    if score >= 70:
        return "Alto"
    if score >= 40:
        return "Médio"
    return "Baixo"

