from app.forensic_engine.parsers.base import UnsupportedVendorParser


class HikvisionParser(UnsupportedVendorParser):
    vendor = "Hikvision"
    markers = ("hikvision", ".dav", ".hik")


def parse(path: str) -> dict[str, object]:
    return HikvisionParser().parse(path)
