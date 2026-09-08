from app.forensic_engine.parsers.base import UnsupportedVendorParser


class HoneywellParser(UnsupportedVendorParser):
    vendor = "Honeywell"
    markers = ("honeywell",)


def parse(path: str) -> dict[str, object]:
    return HoneywellParser().parse(path)
