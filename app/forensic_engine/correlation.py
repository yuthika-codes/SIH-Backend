def correlate(records: list[dict[str, object]], key: str) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for record in records:
        value = str(record.get(key, "unknown"))
        result.setdefault(value, []).append(record)
    return result
