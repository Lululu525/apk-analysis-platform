from __future__ import annotations

import argparse
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from .schemas import AnalyzeRequest, AnalyzeReport


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def validate_json(kind: Literal["request", "report"], in_path: Path) -> None:
    raw = _read_text(in_path)

    try:
        if kind == "request":
            obj = AnalyzeRequest.model_validate_json(raw)
        else:
            obj = AnalyzeReport.model_validate_json(raw)

        # 額外：版本檢查
        if not getattr(obj, "schema_version", "1.0"):
            raise ValueError("schema_version is missing or empty")

        print(f"[OK] {kind} schema valid: {in_path}")
        print(f"     schema_version={obj.schema_version}")

        # 若你想看未知欄位有哪些（extra='allow' 才會有）
        extras = getattr(obj, "model_extra", None)
        if extras:
            print(f"     extra_fields={list(extras.keys())}")

    except ValidationError as e:
        print(f"[FAIL] {kind} schema invalid: {in_path}")
        # 友善輸出：每個錯誤一行
        for err in e.errors():
            loc = ".".join(str(x) for x in err.get("loc", []))
            msg = err.get("msg", "")
            typ = err.get("type", "")
            print(f"  - {loc}: {msg} ({typ})")
        raise SystemExit(1)

    except Exception as e:
        print(f"[FAIL] {kind} schema invalid: {in_path}")
        print(f"  - {e}")
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate request/report JSON schema")
    parser.add_argument("--type", choices=["request", "report"], required=True, help="Schema type to validate")
    parser.add_argument("--in", dest="in_path", required=True, help="Path to JSON file")
    args = parser.parse_args()

    validate_json(args.type, Path(args.in_path))


if __name__ == "__main__":
    main()