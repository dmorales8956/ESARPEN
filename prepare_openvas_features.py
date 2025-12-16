#!/usr/bin/env python3
"""
ESARPEN– scripts/prepare_openvas_features.py (Py3.8)

Objetivo
--------
- Leer `openvas_valid_cves.csv` (lista de CVE válidos detectados por OpenVAS).
- Cargar `data/processed/cves_v2v3.csv` (master NVD con GloVe + CVSS).
- Filtrar por coincidencia exacta de `cve_id`.
- Exportar `data/processed/openvas_v2v3_features.csv` con columnas de features listas para HAL.

Notas
-----
- Detecta automáticamente la columna de CVE en el CSV de OpenVAS (por nombre que contenga "cve" o por búsqueda en el contenido).
- Si algunos CVE de OpenVAS no aparecen en `cves_v2v3.csv`, los lista en un archivo `*_missing.csv`.
- Por defecto exporta: `cve_id`, todas las columnas `glove_*`, y `cvssV2`, `cvssV3` si existen.

Uso rápido
---------
python scripts/prepare_openvas_features.py \
  --processed_dir /home/ubuntu/Documentos/hal9000/data/processed \
  --openvas_csv /home/ubuntu/Documentos/hal9000/data/processed/openvas_valid_cves.csv \
  --out /home/ubuntu/Documentos/hal9000/data/processed/openvas_v2v3_features.csv

Si no pasas argumentos, toma rutas por defecto relativas a este script.
"""

from pathlib import Path
import argparse
import re
import sys
from typing import Optional, Set

import pandas as pd

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GLOVE_PREFIX = "glove_"

# Defaults relativos al script
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROCESSED = (SCRIPT_DIR / ".." / "data" / "processed").resolve()
DEFAULT_OPENVAS = (DEFAULT_PROCESSED / "openvas_valid_cves.csv").resolve()
DEFAULT_CVES = (DEFAULT_PROCESSED / "cves_v2v3.csv").resolve()
DEFAULT_OUT = (DEFAULT_PROCESSED / "openvas_v2v3_features.csv").resolve()


def detect_cve_column(df: pd.DataFrame) -> Optional[str]:
    """Detecta una columna con CVE por nombre (contiene 'cve') o por contenido (regex CVE-YYYY-NNNN)."""
    # 1) por nombre
    for c in df.columns:
        if "cve" in str(c).lower():
            return str(c)
    # 2) por contenido
    for c in df.columns:
        s = df[c].astype(str)
        if s.str.contains("CVE-", case=False, na=False).any():
            return str(c)
    return None


def extract_openvas_cves(path: Path) -> Set[str]:
    # Intentar CSV común, si falla probar TSV
    try:
        df = pd.read_csv(path)
    except Exception:
        df = pd.read_csv(path, sep="\t")

    col = detect_cve_column(df)
    cves: Set[str] = set()

    if col:
        for val in df[col].astype(str):
            for m in CVE_REGEX.findall(val):
                cves.add(m.upper())
    else:
        # Último recurso: buscar en todas las columnas (puede ser más lento)
        for c in df.columns:
            for val in df[c].astype(str):
                for m in CVE_REGEX.findall(val):
                    cves.add(m.upper())
    return cves


def main():
    ap = argparse.ArgumentParser(description="Generar CSV de features para HAL desde OpenVAS y NVD v2v3")
    ap.add_argument("--processed_dir", type=str, default=str(DEFAULT_PROCESSED), help=f"Default: {DEFAULT_PROCESSED}")
    ap.add_argument("--openvas_csv", type=str, default=str(DEFAULT_OPENVAS), help=f"CSV con CVE válidos de OpenVAS (Default: {DEFAULT_OPENVAS})")
    ap.add_argument("--cves_csv", type=str, default=str(DEFAULT_CVES), help=f"Master NVD cves_v2v3.csv (Default: {DEFAULT_CVES})")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT), help=f"Salida (Default: {DEFAULT_OUT})")
    args = ap.parse_args()

    processed_dir = Path(args.processed_dir).resolve()
    openvas_csv = Path(args.openvas_csv).resolve()
    cves_csv = Path(args.cves_csv).resolve()
    out_csv = Path(args.out).resolve()

    if not openvas_csv.exists():
        sys.exit(f"[ERROR] No existe el archivo OpenVAS: {openvas_csv}")
    if not cves_csv.exists():
        sys.exit(f"[ERROR] No existe el master NVD cves_v2v3.csv: {cves_csv}")

    print("Leyendo OpenVAS:", openvas_csv)
    want = extract_openvas_cves(openvas_csv)
    if not want:
        sys.exit("[ERROR] No se detectaron CVE en openvas_csv. Verifica el archivo.")
    print(f"  CVE detectados en OpenVAS: {len(want)}")

    print("Cargando NVD master:", cves_csv)
    df = pd.read_csv(cves_csv)
    if "cve_id" not in df.columns:
        sys.exit("[ERROR] El master NVD no contiene columna 'cve_id'.")

    # Selección de columnas: cve_id + glove_* + (cvssV2, cvssV3 si existen)
    glove_cols = [c for c in df.columns if c.startswith(GLOVE_PREFIX)]
    keep_cols = ["cve_id"] + glove_cols
    for extra in ("cvssV2", "cvssV3"):
        if extra in df.columns:
            keep_cols.append(extra)

    df["cve_id_norm"] = df["cve_id"].astype(str).str.upper()
    df_out = df[df["cve_id_norm"].isin(want)][keep_cols].copy()

    if df_out.empty:
        sys.exit("[ERROR] Ningún CVE de OpenVAS fue encontrado en el master NVD.")

    # Reportar faltantes
    found = set(df.loc[df["cve_id_norm"].isin(want), "cve_id_norm"].unique())
    missing = sorted(want - found)
    if missing:
        miss_path = out_csv.with_name(out_csv.stem + "_missing.csv")
        pd.DataFrame({"cve_id": missing}).to_csv(miss_path, index=False)
        print(f"⚠️  {len(missing)} CVE de OpenVAS no se hallaron en NVD. Detalle: {miss_path}")

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df_out.to_csv(out_csv, index=False)

    print("✅ Guardado:", out_csv)
    print(f"   Filas: {len(df_out)}  |  Cols de features: {len(df_out.columns) - 1}")


if __name__ == "__main__":
    main()
