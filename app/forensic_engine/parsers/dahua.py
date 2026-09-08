from app.forensic_engine.parsers.base import UnsupportedVendorParser


class DahuaParser(UnsupportedVendorParser):
    vendor = "Dahua"
    markers = ("dahua", ".dav", ".dhav")


def parse(path: str) -> dict[str, object]:
    return DahuaParser().parse(path)
