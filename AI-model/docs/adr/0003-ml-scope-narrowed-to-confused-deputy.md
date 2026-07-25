---
status: accepted
---

# 越權 ML 模型範圍收斂到 IPC_CONFUSED_DEPUTY

**Context**：`docs/vector_spec_v1.md`（line 100–104）記錄 `exported=True AND protected=False` 是四條 IPC 規則（`IPC_SERVICE_HIJACK`、`IPC_BROADCAST_THEFT`、`IPC_CONFUSED_DEPUTY`、`IPC_PROVIDER_REDELEGATION`）的共同前提，但只有 `IPC_CONFUSED_DEPUTY` 額外要求「持有危險權限」。比對 30 個 toy APK 的 manifest 設計（`toy_apk_scenario_design.md`）驗證了這一點：Scenario B（Service Hijack）、D（Broadcast Theft）、E（Provider Redelegation）的案例完全不需要（部分甚至完全沒有）宣告危險權限，純粹是「元件曝露且無保護」本身構成風險；只有 Scenario C（Confused Deputy）是「App 持有危險權限 + 曝露元件」的模式，跟 ADR-0001／CONTEXT.md 定義的「元件曝露型越權」（需要 `is_used` 訊號）精確對應。

**Decision**：`filter_row`／Task 9 的 ML label 修正範圍，明確收斂到只處理 `IPC_CONFUSED_DEPUTY` 這一種越權類型。Scenario A（宣告不符型，ADR-0002 已排除）、以及 Scenario B／D／E（共 18 個案例）全部排除在 Task 9 的 ML 訓練範圍外，維持交由 `privilege_rules.py` 的規則引擎處理。30 個 toy 案例裡，真正跟 Task 9／`filter_row` ML 訓練相關的只剩 Scenario C 的 6 個案例。

**Why**：`IPC_SERVICE_HIJACK`／`IPC_BROADCAST_THEFT`／`IPC_PROVIDER_REDELEGATION` 是純粹可從 manifest 直接算出的布林規則（曝露＋未保護，或再加敏感 action 比對），不存在需要學習或推論的空間；用 ML 預測這類本來就能直接算出的目標，正是原始標籤洩漏問題的根源。只有 `IPC_CONFUSED_DEPUTY` 需要「持有危險權限的元件，被觸發後是否真的用到該權限」這種無法單從 manifest 判斷、需要 bytecode 層級推論的訊號，才是 ML／`is_used` 真正有用武之地的地方，也是企劃書「權限是否超出實際功能需求」定義下唯一真正符合「越權」語意的類型。

## Consequences

- `privilege_rules.py` 的 4 條 IPC 規則、風險報告的完整偵測能力**不受影響、繼續運作**；只有 ML 訓練／驗證的範圍縮小到 Scenario C 對應的 `IPC_CONFUSED_DEPUTY`。
- Toy 資料集裡 Scenario B／D／E（18 案例）與 Scenario A（6 案例）不再是 Task 9 的 ML 驗證素材，但仍然是 `privilege_rules.py` 既有規則的 regression test，保留原本用途。
- Task 9 item 2「補上真實敏感 API 呼叫」的工作量大幅縮小：只需處理 Scenario C 的 6 個案例，不用動全部 24 個。
