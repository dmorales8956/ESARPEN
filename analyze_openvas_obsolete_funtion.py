#!/usr/bin/env python3
"""
ESARPEN – scripts/analyze_openvas_obsolete_funtion.py (Py3.8)

Objetivo
========
- Leer `data/raw/report-openvas.csv` (reporte OpenVAS).
- Extraer todos los identificadores **CVE-YYYY-NNNN** de las columnas relevantes.
- Comparar contra **NVD procesado con score** (por defecto `data/processed/cves_all.csv`)
  y dividir en:
    • Reconocidos: existen en NVD y tienen **cvssV2 o cvssV3** (al menos uno).
    • Obsoletos: no tienen score en NVD (no aparecen o tienen ambos NaN).
- Guardar en `data/processed/`:
    • `openvas_valid_cves.csv`     (columna: cve_id)
    • `openvas_obsolete_cves.csv`  (columna: cve_id)

Uso rápido
---------
python scripts/analyze_openvas_obsolete_funtion.py \
  --raw_dir /home/ubuntu/Documentos/hal9000/data/raw \
  --processed_dir /home/ubuntu/Documentos/hal9000/data/processed

Parámetros opcionales:
  --openvas_csv   Ruta al CSV/TSV de OpenVAS (default: <raw_dir>/report-openvas.csv)
  --nvd_csv       Ruta directa al master NVD (default: <processed_dir>/cves_all.csv)
                  Si no existe, el script intentará usar la unión de cves_v2.csv/cves_v3.csv/cves_v2v3.csv.
"""

from pathlib import Path
import argparse
import re
from typing import Optional, Set

import pandas as pd

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Defaults relativos al script
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RAW = (SCRIPT_DIR / ".." / "data" / "raw").resolve()
DEFAULT_PROCESSED = (SCRIPT_DIR / ".." / "data" / "processed").resolve()
DEFAULT_OPENVAS = (DEFAULT_RAW / "report-openvas.csv").resolve()
DEFAULT_NVD_ALL = (DEFAULT_PROCESSED / "cves_all.csv").resolve()


def detect_cve_column(df: pd.DataFrame) -> Optional[str]:
    """Detecta una columna con CVE por nombre (contiene 'cve') o por contenido (regex)."""
    for c in df.columns:
        if "cve" in str(c).lower():
            return str(c)
    for c in df.columns:
        s = df[c].astype(str)
        if s.str.contains("CVE-", case=False, na=False).any():
            return str(c)
    return None


def extract_openvas_cves(path: Path) -> Set[str]:
    """Extrae todos los CVE del CSV/TSV de OpenVAS (únicos, en mayúscula)."""
    try:
        df = pd.read_csv(path)
    except Exception:
        df = pd.read_csv(path, sep="\t")

    cves: Set[str] = set()
    col = detect_cve_column(df)

    if col:
        series = df[col].astype(str)
        for val in series:
            for m in CVE_REGEX.findall(val):
                cves.add(m.upper())
    else:
        # Buscar en todas las columnas como fallback
        for c in df.columns:
            for val in df[c].astype(str):
                for m in CVE_REGEX.findall(val):
                    cves.add(m.upper())

    return cves


def load_nvd_scored_set(nvd_csv: Optional[Path], processed_dir: Path) -> Set[str]:
    """Carga el conjunto de CVE con score (cvssV2 o cvssV3 no nulos).
    Preferencia: nvd_csv (cves_all.csv). Si no existe, unir cves_v2/v3/v2v3.
    """
    scored: Set[str] = set()

    if nvd_csv and nvd_csv.exists():
        usecols = ["cve_id", "cvssV2", "cvssV3"]
        df = pd.read_csv(nvd_csv, usecols=lambda c: c in usecols)
        df["cve_id_norm"] = df["cve_id"].astype(str).str.upper()
        mask = df[[c for c in ["cvssV2", "cvssV3"] if c in df.columns]].notna().any(axis=1)
        scored = set(df.loc[mask, "cve_id_norm"].unique())
        return scored

    # Fallback: unión de archivos por versión
    union_files = [processed_dir / "cves_v2.csv", processed_dir / "cves_v3.csv", processed_dir / "cves_v2v3.csv"]
    found_any = False
    for p in union_files:
        if p.exists():
            found_any = True
            sdf = pd.read_csv(p, usecols=["cve_id"]) if p.name != "cves_v2v3.csv" else pd.read_csv(p, usecols=["cve_id"])  # solo cve_id
            scored.update(sdf["cve_id"].astype(str).str.upper().unique())
    if not found_any:
        raise SystemExit("No se encontró cves_all.csv ni cves_v2/v3/v2v3 en processed_dir.")
    return scored


def main():
    ap = argparse.ArgumentParser(description="Analizar OpenVAS y separar CVE válidos vs obsoletos según NVD–HAL")
    ap.add_argument("--raw_dir", type=str, default=str(DEFAULT_RAW), help=f"Default: {DEFAULT_RAW}")
    ap.add_argument("--processed_dir", type=str, default=str(DEFAULT_PROCESSED), help=f"Default: {DEFAULT_PROCESSED}")
    ap.add_argument("--openvas_csv", type=str, default=str(DEFAULT_OPENVAS), help="CSV/TSV exportado de OpenVAS")
    ap.add_argument("--nvd_csv", type=str, default=str(DEFAULT_NVD_ALL), help="Master NVD (cves_all.csv) con scores")
    args = ap.parse_args()

    raw_dir = Path(args.raw_dir).resolve()
    processed_dir = Path(args.processed_dir).resolve()
    openvas_path = Path(args.openvas_csv).resolve()
    nvd_csv = Path(args.nvd_csv).resolve() if args.nvd_csv else None

    if not openvas_path.exists():
        raise SystemExit(f"No existe el archivo OpenVAS: {openvas_path}")

    print("Leyendo OpenVAS:", openvas_path)
    want = extract_openvas_cves(openvas_path)
    if not want:
        raise SystemExit("No se detectaron CVE en el archivo de OpenVAS.")
    print(f"  CVE detectados (únicos): {len(want)}")

    print("Construyendo conjunto de CVE con score (NVD–HAL)…")
    scored = load_nvd_scored_set(nvd_csv, processed_dir)
    print(f"  CVE con score en NVD–HAL: {len(scored)}")

    valid = sorted([c for c in want if c in scored])
    obsolete = sorted([c for c in want if c not in scored])

    out_valid = processed_dir / "openvas_valid_cves.csv"
    out_obsolete = processed_dir / "openvas_obsolete_cves.csv"
    processed_dir.mkdir(parents=True, exist_ok=True)

    pd.DataFrame({"cve_id": valid}).to_csv(out_valid, index=False)
    pd.DataFrame({"cve_id": obsolete}).to_csv(out_obsolete, index=False)

    print("\n✅ Resultados guardados en:")
    print("  ", out_valid, f"(n={len(valid)})")
    print("  ", out_obsolete, f"(n={len(obsolete)})")

    # Resumen
    total = len(want)
    pct_valid = (len(valid) / total * 100.0) if total else 0.0
    pct_obsolete = (len(obsolete) / total * 100.0) if total else 0.0
    print(f"\nResumen: total={total}  válidos={len(valid)} ({pct_valid:.1f}%)  obsoletos={len(obsolete)} ({pct_obsolete:.1f}%)")


if __name__ == "__main__":
    main()
