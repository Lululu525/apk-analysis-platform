# Android 單一目標 APK 越權風險

本領域聚焦於一次分析一個目標 APK，判斷未受信任的外部呼叫者是否可能透過 Android IPC 觸發目標 App 內缺乏有效授權控制的敏感能力。

## Language

**目標 APK（Target APK）**：
每次分析唯一接受靜態檢查的 Android APK；研究結論只描述此 APK 暴露的風險，不推論外部呼叫者 APK 的實作或惡意性。
_Avoid_：App 內部越權、跨 App chain

**外部呼叫者（External Caller）**：
與目標 APK 不同 UID、沒有目標簽章與特殊系統能力，僅能透過 Android 正常 IPC 介面提供輸入的假設攻擊主體。
_Avoid_：已知惡意 APK、共同分析的第二個 APK

**越權風險路徑（Authorization-Risk Path）**：
從目標 APK 的外部可達 Component entry 出發，受外部輸入影響並到達敏感效果，且途中缺乏有效授權控制的具體候選路徑。
_Avoid_：單一 Intent Filter、單一 exported Component、order-n escalation chain

**Manifest 暴露候選（Manifest Exposure Candidate）**：
由 exported、permission 與相關 Manifest 語意辨識出的待分析入口；它只表示可能外部可達，不等同於越權風險路徑。
_Avoid_：越權真值、漏洞證明

**觀測授權標籤（Observed Authorization Label）**：
由弱規則或標註函數彙整而成、允許帶有雜訊或 abstain 的原始訓練觀測。
_Avoid_：Ground truth、Gold label

**Gold 授權標籤（Gold Authorization Label）**：
依明確威脅模型與可追溯證據獨立覆核出的 positive、negative 或 unknown 決策。
_Avoid_：Malware label、工具 finding、模型預測

**修訂授權標籤（Revised Authorization Label）**：
由 SLB 或其他 label-revision 方法提出的訓練標籤修訂結果；它保留自己的 provenance，且不覆寫 Gold 授權標籤。
_Avoid_：Gold label、已驗證真值

**洩漏基線（Leakage Baseline）**：
使用與弱標籤公式相同或可直接推導該公式的特徵所建立之對照模型，用來展示規則重建造成的虛高效能。
_Avoid_：正式越權偵測器、已驗證模型
