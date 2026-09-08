from app.forensic_engine.parsers.base import UnsupportedVendorParser


class UniviewParser(UnsupportedVendorParser):
    vendor = "Uniview"
    markers = ("uniview",)


def parse(path: str) -> dict[str, object]:
    return UniviewParser().parse(path)
