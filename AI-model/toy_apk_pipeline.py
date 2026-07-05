"""
Toy APK Automation Pipeline
============================
自動化流程：
  1. 產生 Android Studio 專案原始碼
  2. 用 gradlew.bat assembleDebug 自動 build APK
  3. 複製 APK 到 dataset/toy_apks/scenario_x/
  4. 呼叫 app.main pipeline 跑靜態分析
  5. 把驗證報告存成 Markdown

用法：
  python toy_apk_pipeline.py --scenario B --case 0
  python toy_apk_pipeline.py --scenario B --all
  python toy_apk_pipeline.py --scenario A --all

執行環境：在 AI-model/ 目錄下執行
  cd D:\\apk-analysis-platform\\AI-model
  python toy_apk_pipeline.py --scenario B --case 0
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from datetime import datetime

# ==============================================================================
# 路徑設定（全部相對於 AI-model/）
# ==============================================================================

AI_MODEL_ROOT = Path(__file__).parent.resolve()
TOY_APK_SOURCES = AI_MODEL_ROOT / "toy_apk_sources"
TOY_APK_DATASET = AI_MODEL_ROOT / "dataset" / "toy_apks"
PIPELINE_INPUT_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_inputs"
PIPELINE_OUTPUT_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_outputs"
PIPELINE_ARTIFACTS_DIR = AI_MODEL_ROOT / "dataset" / "pipeline_artifacts"
REPORTS_DIR = AI_MODEL_ROOT / "dataset" / "toy_apk_reports"

SDK_DIR = Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk"

# ==============================================================================
# Case 定義
# 每個 scenario 在這裡定義所有 case 的原始碼內容
# ==============================================================================

SCENARIO_CASES = {
    "A": {
        0: {
            "label": 0,
            "note": "對照組：不宣告任何危險權限",
            "permissions_used": [],
            "services": {},
            "check_finding": "OVER_PRIVILEGE",
        },
        1: {
            "label": 1,
            "note": "宣告少量危險權限：CAMERA、READ_CONTACTS",
            "permissions_used": [
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
            ],
            "services": {},
            "check_finding": "OVER_PRIVILEGE",
        },
        2: {
            "label": 0,
            "note": "只宣告 normal/signature 等級權限，非危險權限（INTERNET、ACCESS_NETWORK_STATE、RECEIVE_BOOT_COMPLETED）",
            "permissions_used": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.ACCESS_WIFI_STATE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
            ],
            "services": {},
            "check_finding": "OVER_PRIVILEGE",
        },
        3: {
            "label": 1,
            "note": "宣告跨多個群組的多項危險權限：相機、聯絡人、帳戶、儲存空間",
            "permissions_used": [
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.GET_ACCOUNTS",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
            ],
            "services": {},
            "check_finding": "OVER_PRIVILEGE",
        },
        4: {
            "label": 1,
            "note": "宣告高隱私危險權限：READ_CALL_LOG、RECORD_AUDIO、ACCESS_FINE_LOCATION",
            "permissions_used": [
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
            ],
            "services": {},
            "check_finding": "OVER_PRIVILEGE",
        },
        5: {
            "label": 1,
            "note": "宣告最大範圍危險權限，涵蓋所有高敏感群組（相機、聯絡人、通話記錄、麥克風、位置、簡訊、電話、感測器、儲存空間）",
            "permissions_used": [
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.GET_ACCOUNTS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.READ_PHONE_STATE",
                "android.permission.BODY_SENSORS",
            ],
            "services": {},
            "check_finding": "OVER_PRIVILEGE",
        },
    },
    "B": {
        0: {
            "label": 0,
            "note": "對照組：Service exported=false",
            "manifest_services": textwrap.dedent("""\
                <service
                    android:name=".MyService"
                    android:exported="false" />"""),
            "permissions": [],
            "services": {
                "MyService": "MyService",
            },
        },
        1: {
            "label": 1,
            "note": "Service exported=true 無 permission",
            "manifest_services": textwrap.dedent("""\
                <service
                    android:name=".MyService"
                    android:exported="true" />"""),
            "permissions": [],
            "services": {
                "MyService": "MyService",
            },
        },
        2: {
            "label": 0,
            "note": "Service exported=true 有 signature permission 保護",
            "manifest_permissions": textwrap.dedent("""\
                <permission
                    android:name="com.toyapk.scenario_b.case2.permission.BIND_SERVICE"
                    android:protectionLevel="signature" />"""),
            "manifest_services": textwrap.dedent("""\
                <service
                    android:name=".MyService"
                    android:exported="true"
                    android:permission="com.toyapk.scenario_b.case2.permission.BIND_SERVICE" />"""),
            "permissions": [],
            "services": {
                "MyService": "MyService",
            },
        },
        3: {
            "label": 1,
            "note": "兩個 Service：ProtectedService 有保護；UnprotectedService 無保護（exported）→ rule engine 對 UnprotectedService 觸發 IPC_SERVICE_HIJACK",
            "manifest_permissions": textwrap.dedent("""\
                <permission
                    android:name="com.toyapk.scenario_b.case3.permission.BIND_PROTECTED"
                    android:protectionLevel="signature" />"""),
            "manifest_services": textwrap.dedent("""\
                <service
                    android:name=".ProtectedService"
                    android:exported="true"
                    android:permission="com.toyapk.scenario_b.case3.permission.BIND_PROTECTED" />

                <service
                    android:name=".UnprotectedService"
                    android:exported="true" />"""),
            "permissions": [],
            "services": {
                "ProtectedService": "ProtectedService",
                "UnprotectedService": "UnprotectedService",
            },
        },
        4: {
            "label": 1,
            "note": "Service exported=true 有 intent-filter 無 permission",
            "manifest_services": textwrap.dedent("""\
                <service
                    android:name=".MyService"
                    android:exported="true">
                    <intent-filter>
                        <action android:name="com.toyapk.scenario_b.case4.action.PROCESS" />
                    </intent-filter>
                </service>"""),
            "permissions": [],
            "services": {
                "MyService": "MyService",
            },
        },
        5: {
            "label": 1,
            "note": "兩個 Service 皆 exported 有 intent-filter 無 permission",
            "manifest_services": textwrap.dedent("""\
                <service
                    android:name=".DataSyncService"
                    android:exported="true">
                    <intent-filter>
                        <action android:name="com.toyapk.scenario_b.case5.action.SYNC_DATA" />
                    </intent-filter>
                </service>

                <service
                    android:name=".FileUploadService"
                    android:exported="true">
                    <intent-filter>
                        <action android:name="com.toyapk.scenario_b.case5.action.UPLOAD_FILE" />
                    </intent-filter>
                </service>"""),
            "permissions": [],
            "services": {
                "DataSyncService": "DataSyncService",
                "FileUploadService": "FileUploadService",
            },
        },
    },
    # Scenario C, D, E 之後補在這裡
}

# ==============================================================================
# 檔案產生器
# ==============================================================================

def scenario_lower(scenario: str) -> str:
    return f"scenario_{scenario.lower()}"


def package_name(scenario: str, case_id: int) -> str:
    return f"com.toyapk.scenario_{scenario.lower()}.case{case_id}"


def apk_filename(scenario: str, case_id: int) -> str:
    return f"scenario_{scenario.lower()}_case{case_id}.apk"


def theme_name(scenario: str, case_id: int) -> str:
    return f"Theme.ScenarioCase{scenario}{case_id}"


def generate_manifest(scenario: str, case_id: int, case_def: dict) -> str:
    pkg = package_name(scenario, case_id)
    theme = theme_name(scenario, case_id)
    permission_block = case_def.get("manifest_permissions", "")
    service_block = case_def.get("manifest_services", "")
    permissions_used = case_def.get("permissions_used", [])

    permission_xml = f"\n    {permission_block}\n" if permission_block else ""
    uses_perm_lines = [f'    <uses-permission android:name="{p}" />' for p in permissions_used]
    uses_perm_xml = "\n" + "\n".join(uses_perm_lines) + "\n" if uses_perm_lines else ""
    service_xml = "\n\n        " + service_block.replace("\n", "\n        ") if service_block else ""

    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            xmlns:tools="http://schemas.android.com/tools">
        {permission_xml}{uses_perm_xml}
            <application
                android:allowBackup="true"
                android:dataExtractionRules="@xml/data_extraction_rules"
                android:fullBackupContent="@xml/backup_rules"
                android:icon="@mipmap/ic_launcher"
                android:label="@string/app_name"
                android:roundIcon="@mipmap/ic_launcher_round"
                android:supportsRtl="true"
                android:theme="@style/{theme}">
                <activity
                    android:name=".MainActivity"
                    android:exported="true"
                    android:windowSoftInputMode="adjustResize">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>{service_xml}

            </application>

        </manifest>
        """)


def generate_service_kt(scenario: str, case_id: int, class_name: str) -> str:
    pkg = package_name(scenario, case_id)
    return textwrap.dedent(f"""\
        package {pkg}

        import android.app.Service
        import android.content.Intent
        import android.os.IBinder

        class {class_name} : Service() {{
            override fun onBind(intent: Intent?): IBinder? = null
        }}
        """)


def generate_app_build_gradle(scenario: str, case_id: int) -> str:
    pkg = package_name(scenario, case_id)
    return textwrap.dedent(f"""\
        plugins {{
            alias(libs.plugins.android.application)
            alias(libs.plugins.kotlin.android)
        }}

        android {{
            namespace = "{pkg}"
            compileSdk = 37

            defaultConfig {{
                applicationId = "{pkg}"
                minSdk = 23
                targetSdk = 37
                versionCode = 1
                versionName = "1.0"
            }}

            compileOptions {{
                sourceCompatibility = JavaVersion.VERSION_11
                targetCompatibility = JavaVersion.VERSION_11
            }}
            kotlinOptions {{
                jvmTarget = "11"
            }}
        }}

        dependencies {{
            implementation(libs.androidx.core.ktx)
            implementation(libs.androidx.appcompat)
            implementation(libs.material)
        }}
        """)


def generate_settings_gradle(scenario: str, case_id: int) -> str:
    proj_name = f"ScenarioCase{scenario}{case_id}"
    return textwrap.dedent(f"""\
        pluginManagement {{
            repositories {{
                google()
                mavenCentral()
                gradlePluginPortal()
            }}
        }}
        dependencyResolutionManagement {{
            repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
            repositories {{
                google()
                mavenCentral()
            }}
        }}

        rootProject.name = "{proj_name}"
        include(":app")
        """)


def generate_project_build_gradle() -> str:
    return textwrap.dedent("""\
        plugins {
            alias(libs.plugins.android.application) apply false
            alias(libs.plugins.kotlin.android) apply false
        }
        """)


def generate_gradle_properties() -> str:
    return textwrap.dedent("""\
        org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
        kotlin.code.style=official
        android.useAndroidX=true
        android.suppressUnsupportedCompileSdk=37.1,37.0
        """)


def generate_local_properties() -> str:
    sdk = SDK_DIR.as_posix()
    return f"sdk.dir={sdk}\n"


def generate_libs_versions_toml() -> str:
    return textwrap.dedent("""\
        [versions]
        agp = "8.10.1"
        kotlin = "2.1.20"
        coreKtx = "1.15.0"
        appcompat = "1.7.0"
        material = "1.12.0"

        [libraries]
        androidx-core-ktx = { group = "androidx.core", name = "core-ktx", version.ref = "coreKtx" }
        androidx-appcompat = { group = "androidx.appcompat", name = "appcompat", version.ref = "appcompat" }
        material = { group = "com.google.android.material", name = "material", version.ref = "material" }

        [plugins]
        android-application = { id = "com.android.application", version.ref = "agp" }
        kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "kotlin" }
        """)


def generate_strings_xml(scenario: str, case_id: int) -> str:
    proj_name = f"ScenarioCase{scenario}{case_id}"
    return textwrap.dedent(f"""\
        <resources>
            <string name="app_name">{proj_name}</string>
        </resources>
        """)


def generate_themes_xml(scenario: str, case_id: int, night: bool = False) -> str:
    theme = theme_name(scenario, case_id)
    mode = "dark" if night else "light"
    return textwrap.dedent(f"""\
        <resources xmlns:tools="http://schemas.android.com/tools">
            <style name="Base.{theme}" parent="Theme.Material3.DayNight.NoActionBar">
                <!-- Customize your {mode} theme here. -->
            </style>
            <style name="{theme}" parent="Base.{theme}" />
        </resources>
        """)


def generate_colors_xml() -> str:
    return textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <resources>
            <color name="black">#FF000000</color>
            <color name="white">#FFFFFFFF</color>
        </resources>
        """)


def generate_backup_rules_xml() -> str:
    return textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <full-backup-content>
        </full-backup-content>
        """)


def generate_data_extraction_rules_xml() -> str:
    return textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <data-extraction-rules>
            <cloud-backup>
            </cloud-backup>
        </data-extraction-rules>
        """)


def generate_activity_main_layout() -> str:
    return textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <androidx.constraintlayout.widget.ConstraintLayout
            xmlns:android="http://schemas.android.com/apk/res/android"
            android:layout_width="match_parent"
            android:layout_height="match_parent">
        </androidx.constraintlayout.widget.ConstraintLayout>
        """)


def generate_main_activity(scenario: str, case_id: int) -> str:
    pkg = package_name(scenario, case_id)
    return textwrap.dedent(f"""\
        package {pkg}

        import androidx.appcompat.app.AppCompatActivity
        import android.os.Bundle

        class MainActivity : AppCompatActivity() {{
            override fun onCreate(savedInstanceState: Bundle?) {{
                super.onCreate(savedInstanceState)
            }}
        }}
        """)


# ==============================================================================
# 專案建立
# ==============================================================================

def create_project(scenario: str, case_id: int, case_def: dict) -> Path:
    pkg = package_name(scenario, case_id)
    pkg_path = pkg.replace(".", "/")
    project_dir = TOY_APK_SOURCES / scenario_lower(scenario) / f"case{case_id}"

    print(f"  [1/2] 產生原始碼至{project_dir}")

    # 目錄結構
    src_dir = project_dir / "app" / "src" / "main" / "java" / pkg_path
    src_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "gradle" / "wrapper").mkdir(parents=True, exist_ok=True)

    # 根目錄檔案
    (project_dir / "settings.gradle.kts").write_text(generate_settings_gradle(scenario, case_id), encoding="utf-8")
    (project_dir / "build.gradle.kts").write_text(generate_project_build_gradle(), encoding="utf-8")
    (project_dir / "gradle.properties").write_text(generate_gradle_properties(), encoding="utf-8")
    (project_dir / "local.properties").write_text(generate_local_properties(), encoding="utf-8")
    (project_dir / "gradle" / "libs.versions.toml").write_text(generate_libs_versions_toml(), encoding="utf-8")

    # app/build.gradle.kts
    (project_dir / "app" / "build.gradle.kts").write_text(generate_app_build_gradle(scenario, case_id), encoding="utf-8")

    # AndroidManifest.xml
    manifest_dir = project_dir / "app" / "src" / "main"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "AndroidManifest.xml").write_text(generate_manifest(scenario, case_id, case_def), encoding="utf-8")

    # MainActivity.kt
    (src_dir / "MainActivity.kt").write_text(generate_main_activity(scenario, case_id), encoding="utf-8")

    # Service stubs
    for class_name in case_def.get("services", {}).values():
        kt_content = generate_service_kt(scenario, case_id, class_name)
        (src_dir / f"{class_name}.kt").write_text(kt_content, encoding="utf-8")

    # res/ — 文字資源
    res_dir = project_dir / "app" / "src" / "main" / "res"
    (res_dir / "values").mkdir(parents=True, exist_ok=True)
    (res_dir / "values-night").mkdir(parents=True, exist_ok=True)
    (res_dir / "xml").mkdir(parents=True, exist_ok=True)
    (res_dir / "layout").mkdir(parents=True, exist_ok=True)
    (res_dir / "values" / "strings.xml").write_text(generate_strings_xml(scenario, case_id), encoding="utf-8")
    (res_dir / "values" / "themes.xml").write_text(generate_themes_xml(scenario, case_id, night=False), encoding="utf-8")
    (res_dir / "values-night" / "themes.xml").write_text(generate_themes_xml(scenario, case_id, night=True), encoding="utf-8")
    (res_dir / "values" / "colors.xml").write_text(generate_colors_xml(), encoding="utf-8")
    (res_dir / "xml" / "backup_rules.xml").write_text(generate_backup_rules_xml(), encoding="utf-8")
    (res_dir / "xml" / "data_extraction_rules.xml").write_text(generate_data_extraction_rules_xml(), encoding="utf-8")
    (res_dir / "layout" / "activity_main.xml").write_text(generate_activity_main_layout(), encoding="utf-8")

    # res/ — 二進位資源（mipmap/drawable）：從任何已有的 scenario 複製
    mipmap_dirs = ["drawable", "drawable-v24", "mipmap-anydpi-v26",
                   "mipmap-hdpi", "mipmap-mdpi", "mipmap-xhdpi",
                   "mipmap-xxhdpi", "mipmap-xxxhdpi"]
    for s in SCENARIO_CASES:
        template_res = TOY_APK_SOURCES / scenario_lower(s) / "case0" / "app" / "src" / "main" / "res"
        if not template_res.exists():
            continue
        for mdir in mipmap_dirs:
            src_mdir = template_res / mdir
            dst_mdir = res_dir / mdir
            if src_mdir.exists() and not dst_mdir.exists():
                shutil.copytree(str(src_mdir), str(dst_mdir))
        break  # 只需要一個來源

    return project_dir


# ==============================================================================
# Build APK
# ==============================================================================

def build_apk(project_dir: Path, scenario: str, case_id: int) -> Path:
    print(f"  [2/2] 執行 Gradle build...")

    # Skip build if APK already exists in dataset
    apk_dst_dir = TOY_APK_DATASET / scenario_lower(scenario)
    apk_dst = apk_dst_dir / apk_filename(scenario, case_id)
    if apk_dst.exists():
        print(f"  ✅ APK 已存在，跳過 build：{apk_dst}")
        return apk_dst

    gradlew = project_dir / "gradlew.bat"
    if not gradlew.exists():
        # 嘗試依序從：本 scenario case0 → 其他已知 scenario case0，複製 gradle wrapper
        wrapper_files = ["gradlew", "gradlew.bat", "gradle/wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper.properties"]
        candidate_dirs = [TOY_APK_SOURCES / scenario_lower(scenario) / "case0"]
        for s in SCENARIO_CASES:
            candidate_dirs.append(TOY_APK_SOURCES / scenario_lower(s) / "case0")
        for case0_dir in candidate_dirs:
            if case0_dir == project_dir:
                continue
            for wrapper_file in wrapper_files:
                src = case0_dir / wrapper_file
                dst = project_dir / wrapper_file
                if src.exists() and not dst.exists():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
            if gradlew.exists():
                break

    result = subprocess.run(
        [str(project_dir / "gradlew.bat"), "assembleDebug", "--no-daemon"],
        cwd=str(project_dir),
        capture_output=True,
        text=True,
        shell=True,
    )

    if result.returncode != 0:
        print(f"  ❌ Build 失敗！")
        print(result.stdout[-2000:])
        print(result.stderr[-2000:])
        raise RuntimeError(f"Gradle build failed for {scenario} case{case_id}")

    # 找 APK
    apk_src = project_dir / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
    if not apk_src.exists():
        raise FileNotFoundError(f"找不到 build 產出的 APK：{apk_src}")

    # 複製到 dataset
    apk_dst_dir = TOY_APK_DATASET / scenario_lower(scenario)
    apk_dst_dir.mkdir(parents=True, exist_ok=True)
    apk_dst = apk_dst_dir / apk_filename(scenario, case_id)
    shutil.copy2(apk_src, apk_dst)
    print(f"  ✅ APK 複製至 {apk_dst}")
    return apk_dst


# ==============================================================================
# Pipeline 驗證
# ==============================================================================

def run_pipeline(scenario: str, case_id: int, apk_path: Path) -> dict:
    print(f"  [3/3] 執行 pipeline 驗證...")

    job_id = f"scenario_{scenario.lower()}_case{case_id}"

    PIPELINE_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    PIPELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PIPELINE_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    input_json = {
        "job_id": job_id,
        "sample": {
            "name": apk_path.name,
            "file_path": str(apk_path.relative_to(AI_MODEL_ROOT)).replace("\\", "/"),
        },
        "options": {
            "run_static_scan": True,
            "severity_threshold": "low",
        },
    }

    input_path = PIPELINE_INPUT_DIR / f"{job_id}_input.json"
    output_path = PIPELINE_OUTPUT_DIR / f"{job_id}_output.json"
    artifacts_path = PIPELINE_ARTIFACTS_DIR / job_id

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
        raise RuntimeError(f"Pipeline failed for {scenario} case{case_id}")

    report = json.loads(output_path.read_text(encoding="utf-8"))
    print(f"  ✅ Pipeline 完成，風險分數：{report.get('summary', {}).get('risk_score', 'N/A')}")
    return report


# ==============================================================================
# 報告產生
# ==============================================================================

def generate_report(scenario: str, case_id: int, case_def: dict, report: dict) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    job_id = f"scenario_{scenario.lower()}_case{case_id}"

    check_finding = case_def.get("check_finding", "IPC_SERVICE_HIJACK")
    findings = report.get("findings", [])
    finding_names = [f.get("type", "") for f in findings]
    rule_triggered = any(check_finding in n for n in finding_names)
    expected_label = case_def["label"]
    actual_triggered = 1 if rule_triggered else 0
    match = "✅ PASS" if expected_label == actual_triggered else "❌ FAIL"

    lines = [
        f"# Scenario {scenario} Case {case_id} — 自動產線驗證報告",
        f"",
        f"**產生時間：** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        f"## 基本資訊",
        f"| 欄位 | 值 |",
        f"|------|-----|",
        f"| Job ID | `{job_id}` |",
        f"| Package | `{package_name(scenario, case_id)}` |",
        f"| 風險分數 | {report.get('summary', {}).get('risk_score', 'N/A')} |",
        f"| 風險等級 | {report.get('summary', {}).get('risk_level', 'N/A')} |",
        f"",
        f"## 關鍵驗證",
        f"| 檢查項目 | 預期 | 實際 | 結果 |",
        f"|----------|------|------|------|",
        f"| {check_finding} 觸發 | {'觸發' if expected_label == 1 else '不觸發'} | {'觸發' if rule_triggered else '不觸發'} | {match} |",
        f"",
        f"## 所有 Findings",
        f"| Finding | Severity |",
        f"|---------|----------|",
    ]

    for f in findings:
        lines.append(f"| `{f.get('type', '')}` | {f.get('severity', '')} |")

    lines += ["", f"## 備註", f"{case_def['note']}"]

    report_path = REPORTS_DIR / f"{job_id}_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  📄 報告存至 {report_path}")
    return report_path


# ==============================================================================
# 主流程
# ==============================================================================

def run_case(scenario: str, case_id: int):
    scenario = scenario.upper()
    if scenario not in SCENARIO_CASES:
        print(f"❌ Scenario {scenario} 尚未定義")
        return

    cases = SCENARIO_CASES[scenario]
    if case_id not in cases:
        print(f"❌ Scenario {scenario} Case {case_id} 尚未定義")
        return

    case_def = cases[case_id]
    print(f"\n{'='*60}")
    print(f"  Scenario {scenario} Case {case_id} — {case_def['note']}")
    print(f"{'='*60}")

    project_dir = create_project(scenario, case_id, case_def)
    apk_path = build_apk(project_dir, scenario, case_id)
    report = run_pipeline(scenario, case_id, apk_path)
    generate_report(scenario, case_id, case_def, report)

    print(f"\n✅ Scenario {scenario} Case {case_id} 完成！")


def main():
    parser = argparse.ArgumentParser(description="Toy APK 自動產線")
    parser.add_argument("--scenario", required=True, help="場景代號，例如 B")
    parser.add_argument("--case", type=int, help="Case ID，例如 0")
    parser.add_argument("--all", action="store_true", help="跑該 scenario 的所有 case")
    args = parser.parse_args()

    scenario = args.scenario.upper()

    if args.all:
        if scenario not in SCENARIO_CASES:
            print(f"❌ Scenario {scenario} 尚未定義")
            sys.exit(1)
        for case_id in sorted(SCENARIO_CASES[scenario].keys()):
            run_case(scenario, case_id)
    elif args.case is not None:
        run_case(scenario, args.case)
    else:
        print("❌ 請指定 --case <id> 或 --all")
        sys.exit(1)


if __name__ == "__main__":
    main()
