# AI-model — 安卓 App 越權分析

這個 context 負責分析安卓 APK 是否存在越權風險：從 manifest 與 bytecode 萃取元件資訊，判斷元件是否越權，並訓練 ML 模型輔助規則引擎做風險評分。

## Language

**越權（Over-privilege）**:
一個元件持有的權限，超出其實際功能需求——即該元件被觸發時，並未實際呼叫該權限對應的任何敏感 API。判斷依據是「宣告的權限」與「實際使用的權限」之間的落差，而非單純的 exported/protected 曝露狀態。
_Avoid_: 過度授權（同義詞，統一用越權）、把「exported 且無保護」直接當成越權（那只代表元件可被觸發，不等於越權）

**is_used（權限實際使用狀態）**:
針對單一元件、單一權限計算的布林值：該元件的 class 是否曾作為 caller，呼叫過這個權限所屬敏感 API 群組中的任一 API。逐元件計算，不是整支 App 共用一個值。
_Avoid_: 與 is_declared 混淆——is_declared 只代表 manifest 有宣告該權限，恆為 True 不代表 is_used 也是 True

**敏感 API 群組（Sensitive API Group）**:
KAN-39 模組（`sensitive_api_detector.py`）定義的 API 分類單位（如 `SENSITIVE_API_GPS`、`SENSITIVE_API_CAMERA`），每組包含多個具體 API 呼叫點與其 caller 資訊，是 bytecode 掃描的輸出單位。
_Avoid_: 直接拿權限字串當作分類——權限字串與敏感 API 群組是不同的命名空間，兩者是多對一關係，需靠「permission → group_id 對照表」銜接

**permission → group_id 對照表**:
連接 manifest 權限字串（如 `ACCESS_FINE_LOCATION`）與敏感 API 群組（如 `SENSITIVE_API_GPS`）的映射表，是計算 is_used 與越權 label 的必要黏著層；沒有這張表，敏感 API 掃描結果無法歸因回具體權限。
_Avoid_: 與敏感 API 群組本身混為一談——群組是掃描器的分類單位，這張表才是把群組連回權限字串的橋樑

**label_source**:
`filter_row` 訓練資料的標籤來源標記，區分 `manual`（人工標記，目前為 30 筆 toy APK）與 `rule_weak_label`（規則/公式自動推算，其餘樣本）。訓練與評估時須分別報告兩種來源的表現，不可混為一談。
_Avoid_: 把 `rule_weak_label` 誤認為出自 `privilege_rules.py` 的規則引擎——目前這個標記其實只是 `exported`/`protected` 兩個布林值算出來的公式產物，跟規則引擎無關，語意上是誤導的（這正是 Task 9 要解決的結構性標籤洩漏問題）
