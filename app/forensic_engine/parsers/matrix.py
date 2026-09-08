from app.forensic_engine.parsers.base import UnsupportedVendorParser


class MatrixParser(UnsupportedVendorParser):
    vendor = "Matrix"
    markers = ("matrix",)


def parse(path: str) -> dict[str, object]:
    return MatrixParser().parse(path)
