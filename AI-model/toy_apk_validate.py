"""
Toy APK 驗證腳本
=================
只負責兩件事：
  1. 呼叫 app.main pipeline 跑靜態分析
  2. 把驗證報告存成 Markdown

前提：APK 已手動 build 並放到正確位置：
  AI-model/dataset/toy_apks/scenario_x/scenario_x_case{N}.apk

用法：
  # 驗證單一 case
  python toy_apk_validate.py --scenario B --case 0

  # 驗證整個 scenario
  python toy_apk_validate.py --scenario B --all

  # 驗證單一 APK（不需要 SCENARIO_CASES 定義）
  python toy_apk_validate.py --apk dataset/toy_apks/scenario_a/scenario_a_case0.apk --job-id scenario_a_case0

執行環境：在 AI-model/ 目錄下執行
  cd D:\\apk-analysis-platform\\AI-model
  python toy_apk_validate.py --scenario B --all
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# ==============================================================================
# 路徑設定（全部相對於 AI-model/）
# ==============================================================================

AI_MODEL_ROOT = Path(__file__).parent.resolve()
TOY_APK_DATASET = AI_MODEL_ROOT / "dataset" / "toy_apks"
PIPELINE_INPUT_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_inputs"
PIPELINE_OUTPUT_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_outputs"
PIPELINE_ARTIFACTS_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_artifacts"
REPORTS_DIR = AI_MODEL_ROOT / "dataset" / "toy_apk_reports"

# ==============================================================================
# Case 定義
# 只需要 label 和 note，不需要 manifest 或 Kotlin 內容
# 新增 Scenario 時只需要在這裡補定義
# ==============================================================================

SCENARIO_CASES = {
    "B": {
        0: {"label": 0, "trigger": "IPC_SERVICE_HIJACK", "note": "對照組：Service exported=false"},
        1: {"label": 1, "trigger": "IPC_SERVICE_HIJACK", "note": "Service exported=true 無 permission"},
        2: {"label": 0, "trigger": "IPC_SERVICE_HIJACK", "note": "Service exported=true 有 signature permission 保護"},
        3: {"label": 1, "trigger": "IPC_SERVICE_HIJACK", "note": "兩個 Service：ProtectedService 有保護；UnprotectedService 無保護（exported）→ rule engine 對 UnprotectedService 觸發 IPC_SERVICE_HIJACK"},
        4: {"label": 1, "trigger": "IPC_SERVICE_HIJACK", "note": "Service exported=true 有 intent-filter 無 permission"},
        5: {"label": 1, "trigger": "IPC_SERVICE_HIJACK", "note": "兩個 Service 皆 exported 有 intent-filter 無 permission"},
    },
    "A": {
        # NOTE: trigger 改為 list，採 OR 邏輯（finding_ids 中只要出現任一個就算觸發）。
        # OVER_PRIVILEGE 本身只在宣告 > OVER_PRIVILEGE_THRESHOLD(25) 個危險權限時才會觸發，
        # 是純數量門檻，A-1~A-4 這種少量權限組合案例本來就不會、也不該觸發它。
        # 真正該檢查的是：
        #   - COMBO_* 規則（權限組合語意型偵測，與 25 個門檻無關）
        #   - DANGEROUS_PERMISSIONS_高（單一危險權限本身的高風險 finding）
        # 下面 0/3/5 的 trigger 是暫定的最佳猜測，尚未經過 pipeline 實際輸出確認，
        # 已在對話中特別標註，請 run 過一次後對照 findings 清單確認是否要調整。
        0: {"label": 0, "trigger": ["DANGEROUS_PERMISSIONS_高"], "note": "對照組：只宣告 INTERNET，無危險權限"},
        1: {"label": 1, "trigger": ["COMBO_SMS_EXFIL"], "note": "宣告 READ_SMS + INTERNET（短訊 App 過度宣告）"},
        2: {"label": 1, "trigger": ["COMBO_CONTACT_EXFIL"], "note": "宣告 READ_CONTACTS + CAMERA + INTERNET（計算機 App 過度宣告）"},
        3: {"label": 1, "trigger": ["DANGEROUS_PERMISSIONS_高"], "note": "宣告 ACCESS_FINE_LOCATION（靜態 App，沒有地圖功能）"},
        4: {"label": 1, "trigger": ["COMBO_CALL_INTERCEPT"], "note": "宣告 RECORD_AUDIO + READ_CALL_LOG"},
        5: {"label": 0, "trigger": ["DANGEROUS_PERMISSIONS_高"], "note": "宣告 READ_CONTACTS，但 Activity 有 permission 保護（邊界案例）"},
    },
    "E": {
        0: {"label": 0, "trigger": ["IPC_PROVIDER_REDELEGATION", "IPC_PROVIDER_URI_GRANT_BYPASS"],
            "note": "對照組：Provider exported=false"},
        1: {"label": 1, "trigger": ["IPC_PROVIDER_REDELEGATION"],
            "note": "完全裸露：exported=true 無 readPermission/writePermission"},
        2: {"label": 0, "trigger": ["IPC_PROVIDER_REDELEGATION", "IPC_PROVIDER_URI_GRANT_BYPASS"],
            "note": "完整保護：readPermission+writePermission 皆設定"},
        3: {"label": 1, "trigger": ["IPC_PROVIDER_REDELEGATION"],
            "note": "部分保護：有 readPermission 但無 writePermission"},
        4: {"label": 1, "trigger": ["IPC_PROVIDER_REDELEGATION"],
            "note": "混合案例：一個完整保護、一個完全裸露"},
        5: {"label": 1, "trigger": ["IPC_PROVIDER_URI_GRANT_BYPASS"],
            "note": "URI 授權誤用：兩側皆保護，但 grantUriPermissions=true 可繞過"},
    },
    "C": {
        0: {"label": 0, "trigger": "IPC_CONFUSED_DEPUTY",
            "note": "對照組：持有 READ_SMS 但所有 Activity exported=false"},
        1: {"label": 1, "trigger": "IPC_CONFUSED_DEPUTY",
            "note": "典型 Confused Deputy：READ_SMS + exported Activity 無 permission 保護"},
        2: {"label": 1, "trigger": "IPC_CONFUSED_DEPUTY",
            "note": "相機權限委派：CAMERA + exported Activity 無 permission 保護"},
        3: {"label": 0, "trigger": "IPC_CONFUSED_DEPUTY",
            "note": "正確保護：READ_CONTACTS，MainActivity 與 ContactsActivity 皆有 permission 保護"},
        4: {"label": 1, "trigger": "IPC_CONFUSED_DEPUTY",
            "note": "高嚴重度：READ_SMS + READ_CALL_LOG + 多個 exported Activity 無保護"},
        5: {"label": 0, "trigger": "IPC_CONFUSED_DEPUTY",
            "note": "邊界案例：只有 INTERNET（非危險權限）不觸發規則"},
    },
    "D": {
        # NOTE: IPC_BROADCAST_THEFT 的 finding id 是動態組合的
        # （IPC_BROADCAST_THEFT_{RECEIVER_SHORT_NAME}，見 privilege_rules.py），
        # 這裡的 trigger 用字串 "IPC_BROADCAST_THEFT" 即可，因為 validate 邏輯是
        # `cand in fid` 子字串比對，能對到 IPC_BROADCAST_THEFT_SMSRECEIVER 等
        # 動態 id。此規則是逐一 receiver 判斷（exported + 敏感 action + 無
        # permission），不像 C 的 IPC_CONFUSED_DEPUTY 是 app 層級規則。
        0: {"label": 0, "trigger": "IPC_BROADCAST_THEFT",
            "note": "對照組：Receiver 監聽自訂 action，exported=false"},
        1: {"label": 1, "trigger": "IPC_BROADCAST_THEFT",
            "note": "短訊廣播竊取：SmsReceiver 監聽 SMS_RECEIVED，exported=true 無 permission"},
        2: {"label": 1, "trigger": "IPC_BROADCAST_THEFT",
            "note": "開機廣播竊取：BootReceiver 監聽 BOOT_COMPLETED，exported=true 無 permission"},
        3: {"label": 0, "trigger": "IPC_BROADCAST_THEFT",
            "note": "正確保護：SmsReceiver 監聽 SMS_RECEIVED，有 BROADCAST_SMS permission"},
        4: {"label": 0, "trigger": "IPC_BROADCAST_THEFT",
            "note": "邊界案例：NotificationReceiver 監聽自訂非敏感 action，不觸發規則"},
        5: {"label": 1, "trigger": "IPC_BROADCAST_THEFT",
            "note": "混合案例：ProtectedSmsReceiver 有保護、ExposedBootReceiver 無保護 → 應只有 ExposedBootReceiver 觸發（驗證時建議核對 evidence.receiver 是否確實指向 ExposedBootReceiver）"},
    },
}

# ==============================================================================
# 工具函式
# ==============================================================================

def scenario_lower(scenario: str) -> str:
    return f"scenario_{scenario.lower()}"


def apk_filename(scenario: str, case_id: int) -> str:
    return f"scenario_{scenario.lower()}_case{case_id}.apk"


def package_name(scenario: str, case_id: int) -> str:
    return f"com.toyapk.scenario_{scenario.lower()}.case{case_id}"


def job_id(scenario: str, case_id: int) -> str:
    return f"scenario_{scenario.lower()}_case{case_id}"


# ==============================================================================
# Pipeline 驗證
# ==============================================================================

def run_pipeline(jid: str, apk_path: Path) -> dict:
    print(f"  [1/2] 執行 pipeline 驗證...")

    PIPELINE_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    PIPELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PIPELINE_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    input_json = {
        "job_id": jid,
        "sample": {
            "name": apk_path.name,
            "file_path": str(apk_path.relative_to(AI_MODEL_ROOT)).replace("\\", "/"),
        },
        "options": {
            "run_static_scan": True,
            "severity_threshold": "low",
        },
    }

    input_path = PIPELINE_INPUT_DIR / f"{jid}_input.json"
    output_path = PIPELINE_OUTPUT_DIR / f"{jid}_output.json"
    artifacts_path = PIPELINE_ARTIFACTS_DIR / jid

    input_path.write_text(json.dumps(input_json, ensure_ascii=False, indent=2), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "app.main",
         "--in", str(input_path),
         "--out", str(output_path),
         "--artifacts", str(artifacts_path)],
        cwd=str(AI_MODEL_ROOT),
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"  ❌ Pipeline 失敗！")
        print(result.stderr[-2000:])
        raise RuntimeError(f"Pipeline failed for {jid}")

    report = json.loads(output_path.read_text(encoding="utf-8"))
    risk_score = report.get("summary", {}).get("risk_score", "N/A")
    risk_level = report.get("summary", {}).get("risk_level", "N/A")
    print(f"  ✅ Pipeline 完成，風險分數：{risk_score} / {risk_level}")
    return report


# ==============================================================================
# 報告產生
# ==============================================================================

def _format_evidence(evidence: dict) -> str:
    """把 Finding.evidence 轉成適合放進 Markdown 表格單一儲存格的精簡字串。
    優先抓常見的元件清單欄位（providers/services/receivers/activities/
    components），components 可能是字串或帶 name 欄位的 dict。辨識不出的
    形狀就退回印出精簡 JSON（截斷避免表格被撐爆）。
    """
    if not evidence:
        return ""
    for key in ("providers", "services", "receivers", "activities", "components"):
        values = evidence.get(key)
        if values:
            names = [
                v.get("name", str(v)) if isinstance(v, dict) else str(v)
                for v in values
            ]
            text = "; ".join(names)
            return text.replace("|", "\\|")
    text = json.dumps(evidence, ensure_ascii=False)
    if len(text) > 200:
        text = text[:200] + "…"
    return text.replace("|", "\\|")

def generate_report(jid: str, case_def: dict | None, report: dict, scenario: str = "", case_id: int = -1) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    summary = report.get("summary", {})
    risk_score = summary.get("risk_score", "N/A")
    risk_level = summary.get("risk_level", "N/A")
    counts = summary.get("counts", {})
    findings = report.get("findings", [])
    finding_ids = [f.get("id", "") for f in findings]

    # 驗證邏輯（有 case_def 才做）
    # trigger 可以是單一字串（向後相容）或 list（多個候選 finding id，OR 邏輯：
    # finding_ids 中只要命中其中任一個候選 id 即視為觸發）。
    validation_rows = []
    if case_def:
        trigger = case_def.get("trigger", "")
        trigger_candidates = [trigger] if isinstance(trigger, str) else list(trigger)
        expected_label = case_def["label"]
        triggered = any(
            cand in fid
            for fid in finding_ids
            for cand in trigger_candidates
        )
        actual_label = 1 if triggered else 0
        match = "✅ PASS" if expected_label == actual_label else "❌ FAIL"
        trigger_display = " 或 ".join(trigger_candidates)
        validation_rows = [
            f"| {trigger_display} 觸發 | {'觸發' if expected_label == 1 else '不觸發'} | {'觸發' if triggered else '不觸發'} | {match} |",
        ]

    # 標題
    if scenario and case_id >= 0:
        title = f"# Scenario {scenario} Case {case_id} — 自動產線驗證報告"
        pkg = package_name(scenario, case_id)
    else:
        title = f"# {jid} — 驗證報告"
        pkg = "N/A"

    lines = [
        title,
        "",
        f"**產生時間：** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 基本資訊",
        "| 欄位 | 值 |",
        "|------|-----|",
        f"| Job ID | `{jid}` |",
        f"| Package | `{pkg}` |",
        f"| 風險分數 | {risk_score} |",
        f"| 風險等級 | {risk_level} |",
        f"| Critical | {counts.get('critical', 0)} |",
        f"| High | {counts.get('high', 0)} |",
        f"| Medium | {counts.get('medium', 0)} |",
        "",
    ]

    if validation_rows:
        lines += [
            "## 關鍵驗證",
            "| 檢查項目 | 預期 | 實際 | 結果 |",
            "|----------|------|------|------|",
        ] + validation_rows + [""]

    lines += [
        "## 所有 Findings",
        "| Finding | Severity | Evidence |",
        "|---------|----------|----------|",
    ]
    for f in findings:
        evidence_str = _format_evidence(f.get("evidence") or {})
        lines.append(f"| `{f.get('id', '')}` | {f.get('severity', '')} | {evidence_str} |")

    if case_def and case_def.get("note"):
        lines += ["", "## 備註", case_def["note"]]

    report_path = REPORTS_DIR / f"{jid}_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  📄 報告存至 {report_path}")
    return report_path


# ==============================================================================
# 主流程
# ==============================================================================

def validate_case(scenario: str, case_id: int):
    scenario = scenario.upper()
    cases = SCENARIO_CASES.get(scenario, {})
    case_def = cases.get(case_id)

    apk_path = TOY_APK_DATASET / scenario_lower(scenario) / apk_filename(scenario, case_id)

    if not apk_path.exists():
        print(f"  ❌ APK 不存在：{apk_path}")
        print(f"     請先手動 build 並將 APK 放到正確位置")
        return

    jid = job_id(scenario, case_id)
    print(f"\n{'='*60}")
    print(f"  Scenario {scenario} Case {case_id}{' — ' + case_def['note'] if case_def else ''}")
    print(f"{'='*60}")

    report = run_pipeline(jid, apk_path)
    generate_report(jid, case_def, report, scenario, case_id)

    print(f"\n✅ Scenario {scenario} Case {case_id} 驗證完成！")


def validate_apk(apk_path_str: str, jid: str):
    apk_path = Path(apk_path_str)
    if not apk_path.is_absolute():
        apk_path = AI_MODEL_ROOT / apk_path

    if not apk_path.exists():
        print(f"❌ APK 不存在：{apk_path}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  驗證 APK：{apk_path.name}")
    print(f"{'='*60}")

    report = run_pipeline(jid, apk_path)
    generate_report(jid, None, report)
    print(f"\n✅ 驗證完成！")


def main():
    parser = argparse.ArgumentParser(description="Toy APK 驗證腳本")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scenario", help="場景代號，例如 B（搭配 --case 或 --all）")
    group.add_argument("--apk", help="直接指定 APK 路徑")

    parser.add_argument("--case", type=int, help="Case ID，例如 0")
    parser.add_argument("--all", action="store_true", help="跑該 scenario 的所有 case")
    parser.add_argument("--job-id", help="搭配 --apk 使用的 job ID")

    args = parser.parse_args()

    if args.apk:
        if not args.job_id:
            print("❌ 使用 --apk 時需要指定 --job-id")
            sys.exit(1)
        validate_apk(args.apk, args.job_id)
        return

    scenario = args.scenario.upper()

    if args.all:
        if scenario not in SCENARIO_CASES:
            print(f"⚠️  Scenario {scenario} 在 SCENARIO_CASES 中尚未定義，將跳過關鍵驗證直接跑 pipeline。")
            print(f"   請在腳本的 SCENARIO_CASES 字典中補上定義。")
        cases = SCENARIO_CASES.get(scenario, {})
        if cases:
            for cid in sorted(cases.keys()):
                validate_case(scenario, cid)
        else:
            print(f"❌ Scenario {scenario} 沒有 case 定義，無法使用 --all")
            sys.exit(1)
    elif args.case is not None:
        validate_case(scenario, args.case)
    else:
        print("❌ 請指定 --case <id> 或 --all")
        sys.exit(1)


if __name__ == "__main__":
    main()