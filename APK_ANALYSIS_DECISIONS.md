# APK 分析工具選型決策 & 越權分析路線圖

**日期**: 2026-03-17
**目標**: 澄清工具選擇，對應專題的 Android 越權分析需求

---

## 1. 為什麼選擇 Androguard 而不是 Apktool？

### 工具對比

| 維度 | Apktool | Androguard | 評估 |
|------|---------|-----------|------|
| **語言** | Java | Python 100% | ✅ Androguard (輕量) |
| **安裝難度** | 複雜 (需 Java 環境) | 簡單 (`pip install`) | ✅ Androguard |
| **Manifest 解析** | ✅ 完整 | ✅ 完整 | 平手 |
| **Permission 提取** | ✅ | ✅ | 平手 |
| **Component 圖構建** | ⚠️ 需後處理 | ✅ 直接 API | ✅ Androguard |
| **Intent 分析** | ⚠️ 需自己解析 | ✅ 內置支持 | ✅ Androguard |
| **代碼分析** | 完整反編譯 (smali) | ✅ 字節碼分析 | 取決於需求 |
| **集成度** | 低 (CLI tool) | 高 (Python API) | ✅ Androguard |

### 決策理由

**選擇 Androguard 的原因**:

1. **專題對標**: 你的專題是 **Android 越權分析 (privilege escalation)**
   - 核心需求: 權限 → 組件 → Intent 流 → 風險評分
   - Androguard 直接提供這些 API，無需額外處理

2. **工程化優勢**:
   - 100% Python，無外部依賴
   - 與 FastAPI + pydantic 生態完全相容
   - 易於編排 → 利於並行、分佈式分析

3. **功能覆蓋**:
   ```python
   androguard.misc.AnalyzedAPK
     ├── get_package()              # 包名
     ├── get_permissions()           # ✅ 權限列表
     ├── get_android_manifest_axml() # ✅ Manifest XML
     ├── get_dex()                  # ✅ DEX 字節碼
     └── get_methods()              # ✅ 方法倒查
   ```

4. **已整合的特性**:
   - ✅ Manifest 完整解析
   - ✅ Activity/Service/Provider/Receiver 提取
   - ✅ Intent Filter 分析
   - ✅ 敏感 API 檢測
   - ✅ Risk 評分對應 CWE-927 (Intent 驗證不足)

---

## 2. 為什麼之前的報告說「改用 binwalk」？

這是**涵蓋範圍的問題**，而非工具選擇問題。

### 背景
- **競賽階段** (早期): 平台要求同時支持 **固件 + APK**
  - 固件分析: binwalk (標準工具)
  - APK 分析: Androguard (已在 /requirements.txt)

- **報告誤導點**: 進度文件 "JIRA 需求 3" 在描述「工具轉向」時，只著重於**嵌入式工具鏈**(binwalk/strings/checksec)，沒有充分重視 APK 側的 Androguard。

### 修正
✅ **現在已補正**: AI-model/requirements.txt 加入 androguard

```txt
# 之前
pydantic>=2.0

# 現在 ✅
pydantic>=2.0
androguard>=4.0    # APK analysis for privilege escalation
```

---

## 3. 專題的 APK 分析功能路線

### 當前實現 (已完成)

**文件**: `/AI-model/app/extractors/androguard_analyzer.py`

```python
def analyze_apk(apk_path: Path) → AnalysisResult:
    """
    完整 Androguard APK 分析

    返回:
        ├── 基本信息 (版本, SDK, 包名)
        ├── 權限分析 (危險權限 → 高/中/低風險)
        ├── 組件分析 (Activity/Service/Provider/Receiver)
        ├── Intent 流追蹤 (導出組件的 intent-filter)
        ├── 敏感 API 檢測 (Runtime.exec, reflect, etc)
        └── 風險評分 (CWE 對應)
    """
```

### 數據結構

```python
@dataclass
class PermissionInfo:
    name: str
    risk_level: str          # "高風險" | "中風險" | "低風險"
    is_declared: bool
    is_used: bool
    cwe: str

@dataclass
class ComponentInfo:
    type: str                # "activity" | "service" | "provider" | "receiver"
    name: str
    exported: bool           # ⚠️ 越權風險指標
    intent_filters: List     # 導出入口
    permissions_required: List

@dataclass
class AnalysisResult:
    package_name: str
    version_code/name: str
    min_sdk / target_sdk: int

    permissions: Dict[str, PermissionInfo]
    components: List[ComponentInfo]
    sensitive_api_calls: List[str]
    risk_findings: List[str]  # 越權分析結果
```

### 風險檢測規則 (已實現)

```
✅ 高風險權限聲明
   └─ 位置, 相機, 麥克風, 聯繫人, SMS等

✅ 未受保護的導出組件
   ├─ Activity exported=true, 無 permission 保護
   ├─ Service exported, 無authentication
   └─ ContentProvider authority 未驗證

✅ 敏感 API 調用檢測
   ├─ Runtime.exec() → CWE-78 (OS Command Injection)
   ├─ Reflection invoke() → CWE-95 (Code Injection)
   ├─ Native loadLibrary() → CWE-95
   └─ JavaScript addJavascriptInterface() → CWE-94

✅ 舊 SDK 風險
   └─ targetSdkVersion < 23 → 運行時權限未使用
```

### 對應 HackMD 需求

| HackMD 需求 | 實現方式 | 函數/模組 |
|-----------|---------|---------|
| **APK 驗證** | SHA256 hash + 類型檢測 | `pipeline_apk.py` |
| **Manifest 分析** | Androguard XML 解析 | `androguard_analyzer._extract_*()` |
| **代碼分析** | DEX 字節碼掃描 | `androguard_analyzer._find_sensitive_apis()` |
| **資源分析** | Intent Filter 提取 | `androguard_analyzer._extract_intent_filters()` |
| **Permission Paths** | 組件圖 + 權限對應 | `ComponentInfo.exported` + `permissions_required` |
| **Risk Evaluation** | CWE 規則映射 | `androguard_analyzer._assess_risks()` |
| **可解釋分析** | 結構化 JSON + Finding | `schemas.Finding` + CWE/CVE links |

---

## 4. 與原 pipeline_apk.py 的關係

### 原 pipeline_apk.py (V1)

```
局限性:
- 只做基礎字符串掃描
- 沒有 Manifest 解析
- 沒有 Permission 風險分類
- 沒有組件導出檢測
```

### 升級資料 (V2 路線圖)

```
新 androguard_analyzer.py
      ↓
   [插入 pipeline_apk.py]
      ↓
集成完整的權限+組件+風險分析
      ↓
Finding 返回 CWE-927 (Intent 驗證不足) 等越權相關漏洞
```

### 整合方式

```python
# 在 pipeline_apk.py 中新增

from .extractors.androguard_analyzer import analyze_apk

def run(req, output_dir=None):
    # ... existing code ...

    # 新增: Androguard 完整分析
    apk_analysis = analyze_apk(apk_path)

    if apk_analysis.success:
        # 提取 Finding
        findings.extend(_convert_androguard_findings(apk_analysis))

        # 保存分析結果
        features["androguard"] = {
            "permissions": {...},
            "components": {...},
            "sensitive_apis": [...],
            "risks": [...]
        }
```

---

## 5. 後續開發優先級

### 📌 立即 (本週)

```
[ ] 1. 測試 androguard 集成
      - pip install androguard>=4.0
      - 驗證 AnalyzedAPK() 解析

[ ] 2. 整合到 pipeline_apk.py
      - 添加 androguard 分析步驟
      - 將 AnalysisResult 轉換為 Finding

[ ] 3. 補充 CWE 規則
      - CWE-927: Intent validation misses
      - CWE-276: Incorrect default permissions
      - CWE-919: Improper link resolution before file access
```

### 📌 近期 (2 週)

```
[ ] 4. 動態權限流分析
      - 追蹤 requestPermissions() 調用
      - 識別運行時權限檢查缺失

[ ] 5. Intent 數據流圖
      - 組建組件互動圖
      - 標識越權通道

[ ] 6. 測試用例
      - 已知漏洞 APK 測試集
      - 越權檢測準確性驗證
```

### 📌 後期 (1 月)

```
[ ] 7. ML 模型逐漸調整
      - 結合權限風險 + 組件導出 + API 呼叫
      - 訓練越權風險預測模型

[ ] 8. 報表美化
      - JSON + PDF 輸出
      - 可視化組件圖 & 權限流
```

---

## 6. 快速驗證

```bash
# 1. 安裝依賴
cd /Users/hikaru820/apk-analysis-platform/AI-model
pip install -r requirements.txt

# 2. 測試 androguard_analyzer
python -c "
from app.extractors.androguard_analyzer import analyze_apk
from pathlib import Path

# 使用測試 APK
result = analyze_apk(Path('/path/to/test.apk'))
print(f'Package: {result.package_name}')
print(f'Permissions: {len(result.permissions)}')
print(f'Components: {len(result.components)}')
print(f'Risks: {result.risk_findings}')
"

# 3. 查看完整報告
python -m app.main \
  --in /path/to/request.json \
  --out /path/to/report.json \
  --artifacts ./output
```

---

## 總結

### 決策確認

| 項目 | 決策 | 理由 |
|------|------|------|
| **APK 分析工具** | ✅ Androguard | 專題需求、Python 原生、API 豐富 |
| **APK 反編譯** | ❌ 不使用 Apktool | 不必要 (使用 Androguard 字節碼分析) |
| **固件分析工具** | ✅ binwalk + strings + checksec | 競賽嵌入式環境優化 |
| **版本鎖定** | ✅ Pydantic 2.x, Androguard 4.0+ | 功能完整性 + 穩定性 |

### 專題方向確認

✅ **越權分析專題** (Privilege Escalation Analysis)

```
輸入: APK 檔案
  ↓
[1] Manifest 權限解析
[2] 組件導出分析
[3] Intent 流追蹤
[4] 敏感 API 檢測
  ↓
輸出: 越權風險評分 (CWE-927 等)
    + 組件圖可視化
    + 權限流 JSON
```

---

**文件版本**: 1.0
**最後更新**: 2026-03-17
**下一更新**: 達成立即工作項後
