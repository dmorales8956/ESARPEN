#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ESARPEN – scripts/generate_openvas_report.py (versión enriquecida)

Objetivo:
- Conservar el **formato del reporte HTML** original (secciones 1/2/3) como en tu captura.
- **Añadir** columnas enriquecidas al detalle: Fechas (pub/últ. mod), Impacto (CVSS baseScore),
  Vector de ataque, Privilegios requeridos, Interacción de usuario, Referencias, CPEs, Producto (desde CPE),
  y **CWE**; más los campos KEV (Criticidad/Vulnerability Name/Product/Required Action),
  dejando **Severity** del modelo y **Confidence** intactos.
- Exportar CSV y JSON además del HTML.

Notas de parsing (NVD v2.0):
- En tu dump, `published`, `lastModified`, `metrics`, `references`, `configurations`, `weaknesses` están **dentro de `cve`**.
- CVSS: prioriza V3.1 → V3.0 → V2 (en V2 derivamos `userInteraction` desde `userInteractionRequired`).
- CWE: combina `problemTypes[].descriptions[].{value|cweId}` + `weaknesses[].description[].value`.
- CPE → Producto: `cpe:2.3:*:*:vendor:product:version:...` → tomamos `parts[4]` si no es `*`.
"""

from __future__ import annotations

from pathlib import Path
import json, gzip, argparse, warnings, re
from typing import Dict, Iterable, Optional, Set

import joblib
import pandas as pd
from jinja2 import Template

warnings.filterwarnings("ignore", category=FutureWarning)

# ==========================
# Helpers NVD v2.0
# ==========================

def _open_json_any(path: Path):
    if path.suffix == ".gz" or path.name.endswith(".json.gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")

def _extract_descs_v20(cve_obj: dict) -> Dict[str, str]:
    out = {"es": "", "en": ""}
    try:
        for d in cve_obj.get("descriptions", []) or []:
            lang = str(d.get("lang", "")).lower()
            val = str(d.get("value", "")).strip()
            if lang in ("es", "en") and val:
                out[lang] = val
    except Exception:
        pass
    return out


def build_extended_cve_info(
    raw1_dir: Path,
    target_cves: Set[str],
    cache_path: Optional[Path] = None,
) -> Dict[str, dict]:
    target = {str(c).upper() for c in target_cves}
    out: Dict[str, dict] = {}

    files: Iterable[Path] = sorted(
        list(raw1_dir.rglob("*.json")) + list(raw1_dir.rglob("*.json.gz")),
        key=lambda p: p.name
    )

    scanned_files = 0
    matched = 0

    for fp in files:
        scanned_files += 1
        try:
            with _open_json_any(fp) as f:
                data = json.load(f)
        except Exception:
            continue

        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list):
            continue

        for v in vulns:
            cve = v.get("cve") or {}
            cid = str(cve.get("id", "")).upper()
            if not cid or cid not in target:
                continue

            # Descripción (preferir ES; fallback EN)
            descs = _extract_descs_v20(cve)
            desc_es = descs.get("es") or descs.get("en") or ""

            # Fechas (en tu JSON vienen dentro de cve)
            published = cve.get("published", "")
            modified  = cve.get("lastModified", "")

            # Referencias
            refs = [r.get("url", "") for r in (cve.get("references") or []) if r.get("url")]

            # CWE desde problemTypes y weaknesses
            cwe_set = set()
            for pt in (cve.get("problemTypes") or []):
                for d in (pt.get("descriptions") or []):
                    val = d.get("value") or d.get("cweId") or ""
                    val = str(val).strip()
                    if val:
                        cwe_set.add(val)
            for wk in (cve.get("weaknesses") or []):
                for d in (wk.get("description") or []):
                    val = str(d.get("value", "")).strip()
                    if val:
                        cwe_set.add(val)
            cwe_ids = "; ".join(sorted(cwe_set))

            # Métricas CVSS (cve.metrics o v.metrics)
            metrics = (cve.get("metrics") or v.get("metrics") or {})
            vector = score = privileges = user_interaction = ""
            try:
                if metrics.get("cvssMetricV31"):
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    vector = cvss.get("vectorString", "")
                    score = cvss.get("baseScore", "")
                    privileges = cvss.get("privilegesRequired", "")
                    user_interaction = cvss.get("userInteraction", "")
                elif metrics.get("cvssMetricV30"):
                    cvss = metrics["cvssMetricV30"][0]["cvssData"]
                    vector = cvss.get("vectorString", "")
                    score = cvss.get("baseScore", "")
                    privileges = cvss.get("privilegesRequired", "")
                    user_interaction = cvss.get("userInteraction", "")
                elif metrics.get("cvssMetricV2"):
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]
                    vector = cvss.get("vectorString", "")
                    score = cvss.get("baseScore", "")
                    privileges = "N/A"
                    ui_req = (metrics["cvssMetricV2"][0].get("userInteractionRequired")
                              if isinstance(metrics.get("cvssMetricV2")[0], dict) else None)
                    user_interaction = "Required" if ui_req else ("None" if ui_req is not None else "N/A")
            except Exception:
                pass

            # CPEs y Producto (desde CPE) – mantener el MISMO orden y límite que en la columna CPEs
            cpes_list, seen_cpe = [], set()
            configurations = (cve.get("configurations") or v.get("configurations") or [])
            for cfg in configurations:
                for n in (cfg.get("nodes") or []):
                    for m in (n.get("cpeMatch") or []):
                        cpe = m.get("criteria")
                        if cpe and cpe not in seen_cpe:
                            seen_cpe.add(cpe)
                            cpes_list.append(cpe)
            # Limitar cantidad a mostrar (coherente con el HTML)
            selected_cpes = cpes_list[:5]

            # Extraer productos SOLO de los CPE mostrados
            product_names = []
            seen_prod = set()
            for cpe in selected_cpes:
                parts = cpe.split(":")
                if len(parts) > 4 and parts[4] and parts[4] != "*":
                    prod = parts[4]
                    key = prod.lower()
                    if key not in seen_prod:
                        seen_prod.add(key)
                        product_names.append(prod)

            out[cid] = {
                "desc_es": desc_es,
                "published": published,
                "modified": modified,
                "cvss_score": score,
                "vector": vector,
                "privileges": privileges,
                "interaction": user_interaction,
                "references": "; ".join(list(refs)[:5]),
                "ref_list": list(refs)[:5],
                "cpes": "; ".join(selected_cpes),
                "product_name": "; ".join(product_names),
                "cwe_ids": cwe_ids,
            }
            matched += 1

    if cache_path:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    print(f"[NVD raw1] Archivos inspeccionados: {scanned_files} | CVEs objetivo: {len(target)} | CVEs encontrados: {matched}")
    if matched < len(target):
        missing = list(target - set(out.keys()))[:10]
        print(f"[NVD raw1] ⚠️ No se encontraron {len(target)-matched} CVEs en raw1. Ejemplos: {missing}")

    return out


# ==========================
# Reporte principal (con formato original + columnas nuevas)
# ==========================

def parse_args() -> argparse.Namespace:
    base = Path("/home/ubuntu/Documentos/hal9000")
    ap = argparse.ArgumentParser(description="Generar reporte OpenVAS + HAL (formato original + enriquecido)")
    ap.add_argument("--features_csv", type=Path, default=base / "data/processed/openvas_v2v3_features.csv")
    ap.add_argument("--model_path",   type=Path, default=base / "models/hal_V2pV3_model.pkl")
    ap.add_argument("--out_html",     type=Path, default=base / "reports/Report_recommendations.html")
    ap.add_argument("--out_csv",      type=Path, default=base / "reports/Report_recommendations.csv")
    ap.add_argument("--out_json",     type=Path, default=base / "reports/Report_recommendations.json")
    ap.add_argument("--raw1_dir",     type=Path, default=base / "data/raw1")
    ap.add_argument("--valid_cves_csv",    type=Path, default=base / "data/processed/openvas_valid_cves.csv")
    ap.add_argument("--obsolete_cves_csv", type=Path, default=base / "data/processed/openvas_obsolete_cves.csv")
    ap.add_argument("--nvd_labels_csv",    type=Path, default=base / "data/processed/cves_v2v3_labels.csv")
    ap.add_argument("--kev_json_path",     type=Path, default=base / "data/raw/known_exploited_vulnerabilities.json")
    ap.add_argument("--nvd_text_cache",    type=Path, default=base / "data/processed/nvd_text_index_es_en.json")
    return ap.parse_args()


def generate_openvas_report(
    features_csv: Path,
    model_path: Path,
    out_html: Path,
    out_csv: Path,
    out_json: Path,
    raw1_dir: Path,
    valid_cves_csv: Optional[Path] = None,
    obsolete_cves_csv: Optional[Path] = None,
    nvd_labels_csv: Optional[Path] = None,
    kev_json_path: Optional[Path] = None,
    nvd_text_cache: Optional[Path] = None,
) -> None:
    # 1) Datos + modelo
    df_feats = pd.read_csv(features_csv)
    model = joblib.load(model_path)

    # --- CVEs detectados por OpenVAS: válidos y obsoletos ---
    valid_cves, obsolete_cves = [], []
    try:
        if valid_cves_csv and Path(valid_cves_csv).exists():
            valid_cves = (
                pd.read_csv(valid_cves_csv)["cve_id"].astype(str).str.upper().tolist()
            )
        if obsolete_cves_csv and Path(obsolete_cves_csv).exists():
            obsolete_cves = (
                pd.read_csv(obsolete_cves_csv)["cve_id"].astype(str).str.upper().tolist()
            )
    except Exception:
        pass

    # Si tenemos listado de válidos del escáner, filtramos el features a esos CVE
    if valid_cves:
        df_feats = df_feats[df_feats["cve_id"].astype(str).str.upper().isin(valid_cves)].copy()

    if hasattr(model, "feature_names_in_"):
        need = list(model.feature_names_in_)
        X = df_feats[need].values
    else:
        feat_cols = [c for c in df_feats.columns if c.startswith("glove_")]
        for extra in ("cvssV2", "cvssV3"):
            if extra in df_feats.columns:
                feat_cols.append(extra)
        X = df_feats[sorted(feat_cols)].values

    if hasattr(model, "predict_proba"):
        probas = model.predict_proba(X)
        labels = probas.argmax(axis=1)
        confidences = probas.max(axis=1)
    else:
        labels = model.predict(X)
        confidences = [float("nan")] * len(labels)

    sev_map = {0: "Low", 1: "Medium", 2: "High"}
    df = df_feats.assign(
        Predicted  = labels,
        Confidence = confidences,
        CVE_link   = "https://nvd.nist.gov/vuln/detail/" + df_feats["cve_id"].astype(str),
        _CVE_UP    = df_feats["cve_id"].astype(str).str.upper(),
    )
    df["Severity"] = df["Predicted"].map(sev_map)

    # 2) KEV opcional (como en tu reporte original)
    kev_map: Dict[str, Dict[str, str]] = {}
    if kev_json_path and Path(kev_json_path).exists():
        try:
            kev_data = json.loads(Path(kev_json_path).read_text(encoding="utf-8"))
            vulns = kev_data.get("vulnerabilities", kev_data)
            if isinstance(vulns, list):
                for item in vulns:
                    cid = str(item.get("cveID", "")).upper()
                    if not cid:
                        continue
                    prod = item.get("product", "")
                    if isinstance(prod, list):
                        prod = "; ".join(str(p) for p in prod)
                    kev_map[cid] = {
                        "product": prod or "",
                        "requiredAction": item.get("requiredAction", "") or "",
                        "vulnerabilityName": item.get("vulnerabilityName", "") or "",
                    }
        except Exception:
            pass

    df["in_KEV"]            = df["_CVE_UP"].isin(kev_map.keys())
    df["product"]           = df["_CVE_UP"].map(lambda c: kev_map.get(c, {}).get("product", ""))
    df["requiredAction"]    = df["_CVE_UP"].map(lambda c: kev_map.get(c, {}).get("requiredAction", ""))
    df["vulnerabilityName"] = df["_CVE_UP"].map(lambda c: kev_map.get(c, {}).get("vulnerabilityName", ""))
    df["Criticidad"]        = df["in_KEV"].map({True: "Crítica", False: "No aplica"})

    # >>> FIX: rellenar columnas KEV cuando no aplica (no está en KEV)
    df.loc[~df["in_KEV"], ["vulnerabilityName", "product", "requiredAction"]] = "No aplica"

    # 3) Enriquecimiento desde raw1 (ES/EN + CVSS + CPE + CWE)
    if not raw1_dir.exists():
        raise SystemExit(f"No existe raw1_dir: {raw1_dir}")

    needed = set(df["_CVE_UP"].unique().tolist())
    ext = build_extended_cve_info(raw1_dir, needed, cache_path=nvd_text_cache)

    # mapear columnas nuevas
    map_pairs = [
        ("desc_es", "nvd_description"),
        ("published", "Fecha_Publicacion"),
        ("modified", "Fecha_Modificacion"),
        ("vector", "Vector_Ataque"),
        ("privileges", "Privilegios"),
        ("interaction", "Interaccion_Usuario"),
        ("references", "Referencias"),
        ("cpes", "CPEs"),
        ("product_name", "Producto"),
        ("cwe_ids", "CWE"),
        ("ref_list", "ReferencesLinks"),
    ]
    for k, col in map_pairs:
        df[col] = df["_CVE_UP"].map(lambda c: ext.get(c, {}).get(k, ""))

    # Normalizar y deduplicar Producto (CPE): solo nombre legible
    if "Producto" in df.columns:
        def _norm_cell(cell: str) -> str:
            items = [p.strip() for p in str(cell).split(";") if p.strip()]
            out, seen = [], set()
            for raw in items:
                p = raw.replace("_", " ").strip()
                low = p.lower()
                # eliminar sufijos genéricos ruidosos
                for suf in (" firmware", " software"):
                    if low.endswith(suf):
                        p = p[: -len(suf)].strip()
                        low = p.lower()
                # eliminar tokens de locale si quedaron al final
                for suf in (" en", " ja", " de", " zh-cn", " zh-tw"):
                    if low.endswith(suf):
                        p = p[: -len(suf)].strip()
                        low = p.lower()
                # colapsar espacios
                p = " ".join(p.split())
                key = p.lower()
                if key and key not in seen:
                    seen.add(key)
                    out.append(p)
            return "; ".join(out)
        df["Producto"] = df["Producto"].apply(_norm_cell)

    # 4) Resumen (como tu HTML original)
    total_analyz = len(df)
    total_obsoletes = len(obsolete_cves)

    # === NUEVO: total_reported real desde el CSV original de OpenVAS ===
    RAW_CSV = Path("/home/ubuntu/Documentos/hal9000/data/raw/report-openvas.csv")
    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    def _extract_cves_from_row(row):
        text = []
        for col in ["References", "Other References", "Note", "CVEs", "Vulnerability Insight"]:
            if col in row and pd.notna(row[col]):
                text.append(str(row[col]))
        joined = "  ".join(text)
        return set(m.upper() for m in CVE_PATTERN.findall(joined))

    if RAW_CSV.exists():
        _df_ova = pd.read_csv(RAW_CSV, low_memory=False)
        _df_ova["found_cves"] = _df_ova.apply(_extract_cves_from_row, axis=1)
        _all_openvas_cves = set.union(*_df_ova["found_cves"].tolist()) if not _df_ova.empty else set()
    else:
        _all_openvas_cves = set()

    total_reported = len(_all_openvas_cves)  # <-- valor real (p.ej., 84)

    counts = df["Severity"].value_counts().to_dict()
    avg_conf = float(pd.Series(confidences).mean()) if len(df) else 0.0
    overall_idx = int(round(avg_conf)) if 0 <= round(avg_conf) <= 2 else 1
    overall = sev_map.get(overall_idx, "Medium")
    total_in_kev = int(df["in_KEV"].sum())

    # 5) Orden y columnas del detalle (conservar estructura + nuevas columnas)
    df_sorted = df.sort_values(["in_KEV", "Severity", "Confidence"], ascending=[False, False, False])
    detail_cols = [
        "cve_id",
        "nvd_description",
        "Severity",
        "Confidence",
        "Criticidad",
        "vulnerabilityName",
        "product",
        "requiredAction",
        # Nuevas columnas
        "Vector_Ataque",
        "Privilegios",
        "Interaccion_Usuario",
        "Producto",
        "CPEs",
        "CWE",
        "Fecha_Publicacion",
        "Fecha_Modificacion",
        "Referencias",
        "ReferencesLinks",
        # Link NVD
        "CVE_link",
    ]
    for c in detail_cols:
        if c not in df_sorted.columns:
            df_sorted[c] = "" if c != "Confidence" else float("nan")
    detail = df_sorted[detail_cols].copy()

    # 6) HTML (plantilla original + nuevas columnas)
    tpl = Template(
        """
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Informe modelo IA + OpenVAS (v3)</title>
<style>
  body { font-family: Arial, sans-serif; margin: 20px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f5f5f5; position: sticky; top: 0; }
  .muted { color: #666; }
  .desc { max-width: 900px; }
</style>
</head>
<body>
  <h1>Reporte enriquecido de vulnerabilidades y recomendaciones de controles</h1>

  <h2>1. Cobertura OpenVAS</h2>
  <ul>
    <li><b>Total CVEs reportados por OpenVAS:</b> {{ total_reported }}</li>
    <li><b>Con scoring (analizados):</b> {{ total_analyz }}</li>
    <li><b>Sin scoring (obsoletos):</b> {{ total_obsoletes }}</li>
  </ul>

  <h2>2. Resumen de Predicciones del Modelo</h2>
  <ul>
    <li><b>Total analizados:</b> {{ total_analyz }}</li>
    <li><b>High:</b> {{ counts.get('High', 0) }}</li>
    <li><b>Medium:</b> {{ counts.get('Medium', 0) }}</li>
    <li><b>Low:</b> {{ counts.get('Low', 0) }}</li>
    <li><b>Avg Confidence:</b> {{ '%.2f' % avg_conf }}</li>
    <li><b>Overall risk (aprox.):</b> {{ overall }}</li>
    <li><b>Críticas (en KEV):</b> {{ total_in_kev }}</li>
  </ul>

  <h2>3. Detalle de Vulnerabilidades Analizadas y controles</h2>
  <table>
    <tr>
      <th>CVE ID</th>
      <th class="desc">Description (NVD)</th>
      <th>Severity</th>
      <th>Confidence</th>
      <th>Criticidad (KEV)</th>
      <th>Vulnerability Name (KEV)</th>
      <th>Product (KEV)</th>
      <th>Required Action (KEV)</th>
      <th>Vector de Ataque</th>
      <th>Privilegios</th>
      <th>Interacción Usuario</th>
      <th>Producto (CPE)</th>
      <th>CPEs</th>
      <th>CWE</th>
      <th>Fecha Publicación</th>
      <th>Última Modificación</th>
      <th>Referencias (links)</th>
      <th>Enlace NVD</th>
    </tr>
  {% for row in detail %}
    <tr>
      <td>{{ row.cve_id }}</td>
      <td class="desc">{{ row.nvd_description or '-' }}</td>
      <td>{{ row.Severity }}</td>
      <td>{{ '%.2f'|format(row.Confidence) if row.Confidence==row.Confidence else '-' }}</td>
      <td>{{ row.Criticidad }}</td>
      <td>{{ row.vulnerabilityName or '-' }}</td>
      <td>{{ row.product or '-' }}</td>
      <td>{{ row.requiredAction or '-' }}</td>
      <td>{{ row.Vector_Ataque or '-' }}</td>
      <td>{{ row.Privilegios or '-' }}</td>
      <td>{{ row.Interaccion_Usuario or '-' }}</td>
      <td>{{ row.Producto or '-' }}</td>
      <td>{{ row.CPEs or '-' }}</td>
      <td>{{ row.CWE or '-' }}</td>
      <td>{{ row.Fecha_Publicacion or '-' }}</td>
      <td>{{ row.Fecha_Modificacion or '-' }}</td>
      <td>
        {% if row.ReferencesLinks %}
          {% for url in row.ReferencesLinks %}
            <a href="{{ url }}" target="_blank">{{ url }}</a>{% if not loop.last %}<br>{% endif %}
          {% endfor %}
        {% else %}-{% endif %}
      </td>
      <td><a href="{{ row.CVE_link }}" target="_blank">nvd</a></td>
    </tr>
  {% endfor %}
  </table>

  <p class="muted">Generado por HAL9000.</p>
</body>
</html>
        """
    )

    html = tpl.render(
        total_reported  = total_reported,
        total_analyz    = total_analyz,
        total_obsoletes = total_obsoletes,
        counts          = counts,
        avg_conf        = avg_conf,
        overall         = overall,
        total_in_kev    = total_in_kev,
        detail          = detail.to_dict(orient="records"),
    )

    # 7) Guardar
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html, encoding="utf-8")
    detail.to_csv(out_csv, index=False, encoding="utf-8")
    out_json.write_text(json.dumps(detail.to_dict(orient="records"), ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"✅ Informe HTML: {out_html}")
    print(f"✅ Reporte CSV : {out_csv}")
    print(f"✅ Reporte JSON: {out_json}")


if __name__ == "__main__":
    args = parse_args()
    generate_openvas_report(
        features_csv   = args.features_csv,
        model_path     = args.model_path,
        out_html       = args.out_html,
        out_csv        = args.out_csv,
        out_json       = args.out_json,
        raw1_dir       = args.raw1_dir,
        valid_cves_csv = args.valid_cves_csv,
        obsolete_cves_csv = args.obsolete_cves_csv,
        nvd_labels_csv = args.nvd_labels_csv,
        kev_json_path  = args.kev_json_path,
        nvd_text_cache = args.nvd_text_cache,
    )
