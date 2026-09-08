from app.forensic_engine.parsers.base import UnsupportedVendorParser


class CpPlusParser(UnsupportedVendorParser):
    vendor = "CP Plus"
    markers = ("cpplus", "cp-plus", "cp_plus")


def parse(path: str) -> dict[str, object]:
    return CpPlusParser().parse(path)
