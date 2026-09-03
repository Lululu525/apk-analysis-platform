---
status: accepted
date: 2026-09-03
---

# 將越權偵測限制於單一目標 APK

本專題一次只分析一個目標 APK，並假設一個不同 UID、無目標簽章與特殊系統能力的外部呼叫者。研究目標是辨識此外部呼叫者是否可能透過正常 Android IPC，到達目標 APK 的 Component entry、以外部輸入影響敏感效果，且在路徑上缺乏有效授權控制；選擇此範圍是為了對齊原始的單一 App 越權風險目標，同時避免把 El-Zawawy 與 Hamdy 論文的 order-n multi-app escalation chain 當成本專題必須重現的工作。

## 決策

- 最終可標註與評估的 prediction unit 是目標 APK 內的 concrete Component entry-to-sensitive-effect path，而不是 APK 整體、單一 Intent Filter 或跨 APK chain。
- Gold positive 必須同時具有 external reachability、attacker-controlled input influence、sensitive effect reachability 與 authorization failure 的足夠證據；任一條件被可靠 refute 時為 negative，證據不足且未被 refute 時為 unknown。
- `exported && !protected`、`risk_hint`、工具 finding 與 malware/benign metadata 只能提供候選或 weak evidence，不能單獨產生 Gold。
- 原始 Random Forest 保留為洩漏基線；`observed_authz_label`、`gold_authz_label` 與 `revised_authz_label` 必須維持不同語意與 provenance。
- SLB 是後續用來研究 weak-label revision 的方法，不負責定義越權、不產生 Gold，也不在 candidate/path 與獨立評估成立前啟動。

## Considered Options

- **採用：single-target-APK Component-path risk。** 保留外部 caller 的 privilege boundary，但不要求取得或共同分析 caller APK。
- **不採用：order-n multi-app escalation chain。** 這是參考論文的重要研究範圍，但不是本專題原始要回答的問題。
- **不採用：以 APK malware/benign 分類代替 authorization risk。** APK 惡意性與某條 Component path 是否可造成未授權敏感效果是不同標籤軸。
- **不採用：以 Manifest exposure 直接定義越權。** Exported 且缺少明確 Component permission 只足以產生候選，不能證明 attacker input、sensitive effect 與 guard failure。

## Consequences

- 近期先驗證 controlled toy cases 能否區分 Manifest exposure、真實 Authorization-Risk Path 與 unknown；在此之前暫停 6-APK framework paired benchmark、50-APK Golden review、外部 framework 整合與 SLB 實作。
- MobSF、FlowDroid 或其他 framework 只有在 toy validation 顯示特定 evidence gap，且 bounded PoC 能回答該缺口時才重新評估。
- 舊計畫與既有產物保留為歷史證據；若其執行順序與本 ADR 衝突，以本 ADR 和 `docs/SLB越權偵測實作時程.md` 的 scope-reset 區段為準。
