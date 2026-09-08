from app.models.case import Case


def build_case_report(case: Case) -> dict[str, object]:
    return {
        "case_id": case.id,
        "title": case.title,
        "status": case.status,
        "generated": False,
    }
