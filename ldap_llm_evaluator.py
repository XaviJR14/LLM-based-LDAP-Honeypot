#!/usr/bin/env python3
"""
LDAP LLM: Always Evaluate; Optional Inference

This script ALWAYS runs the evaluation. Inference is OPTIONAL and only runs
when explicitly requested.

Two input pathways:
  A) --infer with --in  : Read a CSV with [input, output], run inference via
                          `send_ldap_to_colab` to create predictions, save
                          [input, output, prediction] to --out-preds, THEN evaluate.
  B) (no --infer) with --data : Read a CSV that already has [input, output, prediction]
                          and evaluate directly (no inference).

Notes
- `send_ldap_to_colab` receives the LDAP request as a JSON STRING and returns a
  list of JSON strings (each an LDAPMessage). We join them with newlines.
- Evaluation is protocol-aware (syntax/structure/key fields/completeness).
- CSV separator is auto; force with --sep ';' if needed.

Examples
  # Run inference first and then evaluate
  python ldap_llm_evaluator.py --infer --in evaluation_dataset.csv --out-preds preds.csv --report report.csv --summary summary.json --sep ';' --asn1

  # Evaluate an existing file with predictions
  python ldap_llm_evaluator.py --data preds.csv --report report.csv --summary summary.json --sep ';' --asn1
"""
from __future__ import annotations
import argparse
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import math


# Import the streaming client used in your honeypot integration
from ldap_colab_client import send_ldap_to_colab

# Optional ASN.1 imports (enabled via --asn1)
HAVE_ASN1 = False
try:
    from pyasn1_ldap import rfc4511
    from pyasn1.codec.native import decoder as native_decoder
    HAVE_ASN1 = True
except Exception:
    HAVE_ASN1 = False

# ===================== JSON helpers =====================

def split_concatenated_json(raw: str) -> List[Dict[str, Any]]:
    """Split a string that may contain one or more JSON objects.
    Accepts plain JSON, JSONL (one object per line), or concatenated objects.
    """
    if not isinstance(raw, str):
        raise ValueError("Prediction must be a string containing JSON.")

    s = raw.strip()
    # Try direct parse first
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
    except json.JSONDecodeError:
        pass

    # Try JSONL
    objs: List[Dict[str, Any]] = []
    lines = [ln for ln in s.splitlines() if ln.strip()]
    if len(lines) > 1:
        ok = True
        for ln in lines:
            try:
                obj = json.loads(ln)
                if isinstance(obj, dict):
                    objs.append(obj)
                else:
                    ok = False
                    break
            except json.JSONDecodeError:
                ok = False
                break
        if ok and objs:
            return objs

    # Fallback: streaming raw_decode
    dec = json.JSONDecoder()
    i, n = 0, len(s)
    while i < n:
        j = s.find('{', i)
        if j == -1:
            break
        try:
            obj, idx = dec.raw_decode(s, j)
            if isinstance(obj, dict):
                objs.append(obj)
            i = idx
        except json.JSONDecodeError:
            break
    if not objs:
        raise json.JSONDecodeError("Could not parse any JSON object", s, 0)
    return objs


def safe_load_json_obj(raw: str) -> Dict[str, Any]:
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("Expected a single JSON object in 'input'.")
    return obj

# ===================== LDAP protocol helpers =====================

def detect_request_op(request_obj: Dict[str, Any]) -> Optional[str]:
    op = request_obj.get("protocolOp")
    if isinstance(op, dict) and op:
        return next(iter(op.keys()))
    return None


def list_response_ops(objs: List[Dict[str, Any]]) -> List[str]:
    kinds: List[str] = []
    for o in objs:
        op = o.get("protocolOp")
        if isinstance(op, dict) and op:
            kinds.append(next(iter(op.keys())))
    return kinds


def count_search_entries(objs: List[Dict[str, Any]]) -> int:
    return sum(1 for o in objs if isinstance(o.get("protocolOp"), dict) and "searchResEntry" in o["protocolOp"])


def has_search_done(objs: List[Dict[str, Any]]) -> bool:
    return any(isinstance(o.get("protocolOp"), dict) and "searchResDone" in o["protocolOp"] for o in objs)

# ===================== Rule checks =====================

def check_syntax(pred_raw: str, require_asn1: bool) -> Tuple[int, List[Dict[str, Any]]]:
    """Return (pass_flag, parsed_objects). JSON parsing + optional ASN.1 native decode."""
    try:
        objs = split_concatenated_json(pred_raw)
    except Exception:
        return 0, []

    if require_asn1:
        if not HAVE_ASN1:
            raise RuntimeError("ASN.1 validation requested but pyasn1_ldap is not available.")
        try:
            for obj in objs:
                native_decoder.decode(obj, asn1Spec=rfc4511.LDAPMessage())
        except Exception:
            return 0, objs

    return 1, objs


def check_structure(request_op: str, pred_objs: List[Dict[str, Any]]) -> int:
    """
    Structure check (strict):
      - abandonRequest -> expects NO responses at all
      - bindRequest -> ALL ops must be exactly {bindResponse}
      - searchRequest -> ALL ops must be in {searchResEntry, searchResDone}; NOT requiring Done here
                         (completeness is scored in check_completeness)
      - mapped ops (modify/add/del/modDN/compare) -> ALL ops must be exactly the single expected response
      - unknown -> require at least one protocolOp present (best-effort)
    """
    # --- Strict handling for abandonRequest: expects no responses ---
    if request_op == "abandonRequest":
        # Any response makes it invalid; zero responses is valid.
        return 1 if not pred_objs else 0

    # For all other requests, if there is no response at all, structure fails.
    if not pred_objs:
        return 0

    if request_op == "bindRequest":
        kinds = set(list_response_ops(pred_objs))
        # Only bindResponse is allowed, no extras.
        return 1 if kinds and kinds.issubset({"bindResponse"}) else 0

    if request_op == "searchRequest":
        kinds = list_response_ops(pred_objs)
        allowed = {"searchResEntry", "searchResDone"}
        # Any op outside the allowed set invalidates the structure.
        if any(k not in allowed for k in kinds):
            return 0
        # All ops are valid for search responses; pass structure.
        return 1

    mapping = {
        "modifyRequest": "modifyResponse",
        "addRequest": "addResponse",
        "delRequest": "delResponse",
        "modDNRequest": "modDNResponse",
        "compareRequest": "compareResponse",
    }
    if request_op in mapping:
        expect = mapping[request_op]
        kinds = set(list_response_ops(pred_objs))
        # All ops must be exactly the expected one (no extras).
        return 1 if kinds and kinds.issubset({expect}) else 0

    # Unknown op → best-effort: require at least one protocolOp
    return 1 if any(isinstance(o.get("protocolOp"), dict) and o["protocolOp"] for o in pred_objs) else 0



def check_key_fields(request_obj: Dict[str, Any],
                     output_objs: Optional[List[Dict[str, Any]]],
                     pred_objs: List[Dict[str, Any]]) -> float:
    """
    Key fields score with asymmetric treatment of messageID:
    - We do NOT reward a correct messageID (it's common); factor=1.0 when all match.
    - We DO penalize heavily when messageID is wrong/partial.

    Final score = op_agreement * mid_penalty

    Where:
      - op_agreement: Jaccard agreement of response op kinds (w.r.t. expected output if available).
      - mid_penalty:
          = 1.0                      if all messageIDs match
          = (mid_fraction ** EXP)    otherwise (steep penalty as mid_fraction drops)

    Tunables:
      - EXP: controls how steep the penalty is when messageID mismatches appear.
             3 is a good default: 0.8^3=0.512, 0.5^3=0.125, 0.0^3=0.0.
    """
    if not pred_objs:
        return 0.0

    # --- Compute op_agreement (dominant component) ---
    # If expected output is available, use Jaccard of op kinds; otherwise, assume full agreement (1.0).
    if output_objs:
        out_kinds = set(list_response_ops(output_objs))
        pred_kinds = set(list_response_ops(pred_objs))
        union = len(out_kinds | pred_kinds) or 1
        op_agreement = len(out_kinds & pred_kinds) / union
    else:
        op_agreement = 1.0

    # --- Compute messageID penalty (asymmetric) ---
    req_mid = request_obj.get("messageID", None)

    if req_mid is None:
        # No messageID in request → do not penalize predictions for this dimension.
        mid_penalty = 1.0
    else:
        total = len(pred_objs)
        mid_ok = sum(1 for o in pred_objs if o.get("messageID") == req_mid)
        mid_fraction = mid_ok / total if total else 0.0

        if mid_fraction >= 1.0:
            # All messageIDs correct → no extra reward, just no penalty.
            mid_penalty = 1.0
        else:
            # Heavily penalize partial/incorrect messageIDs.
            EXP = 3
            mid_penalty = (mid_fraction ** EXP) if mid_fraction > 0.0 else 0.0

    return float(op_agreement * mid_penalty)


def check_completeness(request_obj: Dict[str, Any],
                       output_objs: Optional[List[Dict[str, Any]]],
                       pred_objs: List[Dict[str, Any]]) -> float:
    """
    Completeness score.

    - For searchRequest:
        * With expected output: entry coverage vs expected + presence of searchResDone.
        * Without expected output: infer from sizeLimit and require Done presence.
    - For non-search requests:
        * Return NaN (N/A). We do not want to grant free points here; the weighted
          score will redistribute this weight to 'structure' to keep strictness.
    """
    request_op = detect_request_op(request_obj)

    if request_op != "searchRequest":
        # Mark as N/A — handled in evaluate_sample weighting.
        return math.nan

    pred_entries = count_search_entries(pred_objs)
    pred_has_done = has_search_done(pred_objs)

    if output_objs:
        exp_entries = count_search_entries(output_objs)
        entry_cov = min(1.0, pred_entries / exp_entries) if exp_entries > 0 else 1.0
        done_ok = 1.0 if pred_has_done else 0.0
        return 0.7 * entry_cov + 0.3 * done_ok

    # No expected output → use request hints
    sr = request_obj.get("protocolOp", {}).get("searchRequest", {})
    size_limit = 0
    try:
        size_limit = int(sr.get("sizeLimit", 0) or 0)
    except Exception:
        size_limit = 0
    expected = min(size_limit, 10) if size_limit > 0 else 1
    entry_cov = min(1.0, pred_entries / expected) if expected > 0 else 1.0
    done_ok = 1.0 if pred_has_done else 0.0
    return 0.7 * entry_cov + 0.3 * done_ok

# ===================== Evaluation core =====================
@dataclass
class SampleResult:
    syntax_pass: int
    structure_pass: int
    key_fields: float
    completeness: float
    weighted_score: float


def evaluate_sample(inp_raw: str, output_raw: Optional[str], pred_raw: str, require_asn1: bool) -> SampleResult:
    request_obj = safe_load_json_obj(inp_raw)

    syntax_ok, pred_objs = check_syntax(pred_raw, require_asn1=require_asn1)

    output_objs: Optional[List[Dict[str, Any]]] = None
    if output_raw is not None and isinstance(output_raw, str) and output_raw.strip():
        try:
            output_objs = split_concatenated_json(output_raw)
        except Exception:
            output_objs = None

    if syntax_ok:
        request_op = detect_request_op(request_obj)
        structure_ok = check_structure(request_op, pred_objs)
        key_fields = check_key_fields(request_obj, output_objs, pred_objs)
        completeness = check_completeness(request_obj, output_objs, pred_objs)
    else:
        # If syntax fails, everything else contributes zero.
        structure_ok = 0
        key_fields = 0.0
        completeness = 0.0

    # --- Dynamic weighting ---
    # Base weights: syntax=0.4, structure=0.3, key_fields=0.2, completeness=0.1
    if syntax_ok and isinstance(completeness, float) and math.isnan(completeness):
        # Non-search
        weighted = 0.4*syntax_ok + 0.4*structure_ok + 0.2*key_field
    else:
        weighted = 0.4 * syntax_ok + 0.3 * structure_ok + 0.2 * key_fields + 0.1 * completeness

    return SampleResult(
        syntax_pass=int(syntax_ok),
        structure_pass=int(structure_ok),
        key_fields=float(round(key_fields, 4)),
        completeness=float(round(completeness, 4)) if not (isinstance(completeness, float) and math.isnan(completeness)) else math.nan,
        weighted_score=float(round(weighted, 4)),
    )


def aggregate_results(df: pd.DataFrame) -> Dict[str, float]:
    agg = {
        "syntax_pass_rate": df["syntax_pass"].mean() if len(df) else 0.0,
        "structure_pass_rate": df["structure_pass"].mean() if len(df) else 0.0,
        "key_fields_mean": df["key_fields"].mean() if len(df) else 0.0,
        "completeness_mean": df["completeness"].mean() if len(df) else 0.0,
        "weighted_score_mean": df["weighted_score"].mean() if len(df) else 0.0,
    }
    return {k: float(round(v, 4)) for k, v in agg.items()}

# ===================== Inference (optional) =====================

def run_inference_on_inputs(in_path: str, out_preds_path: str, sep: Optional[str]) -> str:
    """Run inference via send_ldap_to_colab for each input in [input, output].
    Returns the path to the produced [input, output, prediction] CSV.
    """
    df = pd.read_csv(in_path, sep=sep)
    required = {"input", "output"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in --in CSV: {missing}")

    predictions: List[str] = []

    for idx, row in df.iterrows():
        inp = row["input"]
        if not isinstance(inp, str) or not inp.strip():
            predictions.append("")
            continue
        try:
            # send_ldap_to_colab expects a JSON string (as in ldap_parser_and_responder.py)
            msgs: List[str] = send_ldap_to_colab(inp)
            pred = "\n".join(m.strip() for m in msgs if isinstance(m, str) and m.strip())
            predictions.append(pred)
            print(f"[+] Inferred row {idx} with {len(msgs)} message(s)")
        except Exception as e:
            print(f"[!] Inference failed for row {idx}: {e}")
            predictions.append("")

    pred_df = pd.DataFrame({
        "input": df["input"],
        "output": df["output"],
        "prediction": predictions,
    })
    pred_df.to_csv(out_preds_path, index=False)
    print(f"[✓] Wrote predictions to: {out_preds_path}")
    return out_preds_path

# ===================== Evaluate (always) =====================

def run_evaluation(data_path: str, report_path: str, summary_path: str, sep: Optional[str], require_asn1: bool) -> None:
    #df = pd.read_csv(data_path, sep=sep)
    df = pd.read_csv(data_path, sep=sep if sep else ",", encoding="cp1252", engine="python")
    required = {"input", "output", "prediction"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in --data CSV: {missing}")

    results: List[SampleResult] = []
    for _, row in df.iterrows():
        try:
            res = evaluate_sample(
                inp_raw=row["input"],
                output_raw=row["output"],
                pred_raw=row["prediction"],
                require_asn1=require_asn1,
            )
        except Exception:
            res = SampleResult(0, 0, 0.0, 0.0, 0.0)
        results.append(res)

    out_df = df.copy()
    out_df["syntax_pass"] = [r.syntax_pass for r in results]
    out_df["structure_pass"] = [r.structure_pass for r in results]
    out_df["key_fields"] = [r.key_fields for r in results]
    out_df["completeness"] = [r.completeness for r in results]
    out_df["weighted_score"] = [r.weighted_score for r in results]

    out_df.to_csv(report_path, index=False)

    summary = aggregate_results(out_df)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("=== Aggregated Metrics ===")
    for k, v in summary.items():
        print(f"{k}: {v}")
    print(f"Per-sample report: {report_path}")
    print(f"Summary: {summary_path}")

# ===================== CLI =====================

def main():
    p = argparse.ArgumentParser(description="LDAP LLM: Always Evaluate; Optional Inference")
    p.add_argument("--infer", action="store_true", help="Run inference with send_ldap_to_colab before evaluation")
    p.add_argument("--in", dest="in_path", help="CSV with columns [input, output] (required if --infer)")
    p.add_argument("--out-preds", dest="out_preds", default="preds.csv", help="Where to write [input, output, prediction] when inferring")
    p.add_argument("--data", help="CSV with [input, output, prediction] (used when not inferring)")
    p.add_argument("--report", default="evaluation_report.csv", help="Per-sample evaluation CSV")
    p.add_argument("--summary", default="evaluation_summary.json", help="Aggregated metrics JSON")
    p.add_argument("--sep", default=None, help="CSV separator override (e.g., ';')")
    p.add_argument("--asn1", action="store_true", help="Enable ASN.1 validation (requires pyasn1_ldap)")

    args = p.parse_args()

    # Decide data source
    if args.infer:
        if not args.in_path:
            raise ValueError("--infer requires --in <CSV with [input, output]>")
        data_csv = run_inference_on_inputs(args.in_path, args.out_preds, sep=args.sep)
    else:
        if not args.data:
            raise ValueError("Provide --data <CSV with [input, output, prediction]> or use --infer with --in.")
        data_csv = args.data

    if args.asn1 and not HAVE_ASN1:
        raise RuntimeError("--asn1 requested but pyasn1_ldap is not installed.")

    # ALWAYS run evaluation
    run_evaluation(data_csv, args.report, args.summary, sep=args.sep, require_asn1=args.asn1)


if __name__ == "__main__":
    main()
