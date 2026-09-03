# 現成 Mobile Security Framework 重用評估：MobSF、Androguard 與深度資料流工具

- 查核日期：2026-08-25（Asia/Taipei）
- 文件性質：技術選型研究筆記；不是 production integration spec，也不是法律意見
- 查核範圍：官方文件、官方原始碼庫、官方 release/package metadata 與論文原文
- 專題範圍：Android component-path authorization-risk evidence pipeline 與後續 SLB；不以 APK malware/benign classification 取代 authorization label
- 執行狀態：**deferred（2026-09-03）**；本文件保留為工具能力參考，不代表目前已決定整合 MobSF、FlowDroid 或其他 framework。依 [`ADR-0001`](../adr/0001-single-target-apk-authorization-risk.md)，先以 controlled toy cases 找出 single-target-APK evidence gap，再決定是否重啟 bounded PoC。

## 一、結論先行

可以重用現成框架，但不應把任何一套框架「整包當成我們的越權偵測器」，更不能把其 finding、risk score、source-to-sink trace 或 malware verdict 當成 `gold_authz_label`。

建議採取 **adopt engines, build the evidence contract** 的混合路線：

1. **保留並版本固定 Androguard**，繼續負責 APK/Manifest/DEX/XREF 的低階抽取。這是 repo 已採用且整合成本最低的底座。
2. **優先以 FlowDroid 做一個 bounded deep-path PoC**，補目前最明顯的跨方法 attacker-input-to-sensitive-sink 缺口；只匯入可追溯的 path evidence，不匯入「漏洞結論」。它官方支援 Windows、macOS、Linux，對目前 Windows 開發環境較容易先驗證。
3. **把 Mariana Trench 當第二個 deep-taint 候選或交叉驗證器**。它的 `Activity.getIntent` → sensitive sink trace 與本專題的 I/S evidence 很對齊，設定也很彈性；但現行 PyPI 1.0.8 只有 manylinux x86-64 與 macOS x86-64 wheel，Windows 端需移至 Linux VM/container 或自行建置。
4. **MobSF 只以獨立 sidecar/service 評估**：使用固定版本 Docker image + REST API 取得 Manifest、component、permission、code/manifest findings、decompiled artifacts 等 enrichment，作為 parser cross-check、candidate generation 與人工 triage 輔助。不要 fork MobSF 來承載本專題 label semantics，也不要把 MobSF finding/score 當 model target。
5. **Amandroid/Argus-SAF 暫不列第一順位**。它的 ICC/data-flow 架構在概念上合適且採 Apache-2.0，但官方 repo 要求 Java 10、最後可見更新停在 2023，release v3.1.3 仍自稱下一個 major release 的 pre-release；導入風險高於 FlowDroid/Mariana Trench。
6. 本 repo 仍需自行擁有、測試與版本化：canonical SHA-256 identity、component/path identity、R/I/S/A predicates、guard effectiveness、evidence status/reason codes、`observed_authz_label`／`gold_authz_label`／`revised_authz_label` 分離、50 APK Golden evaluation 與 SLB。

換句話說，**「直接拿 MobSF 來掃」可行；「直接拿 MobSF 報告當我們的越權答案」不可行**。最值得省下來的是 parsing、decompilation、call/data-flow engine、API orchestration 與報告瀏覽；最不能外包的是研究問題、威脅模型、證據契約、標籤與 evaluation。

## 二、repo 的實際需求與目前缺口

本評估不是用一般「Android 安全掃描器功能很多」作為選型依據，而是對齊目前 checkout 的實際介面與 label 規格。

### 2.1 本專題真正要回答的問題

依 [`authz_label_spec.md`](../authz_label_spec.md)，一筆可標註的 concrete component-path 至少要有：

```text
APK SHA-256
+ Manifest component identity
+ resolved code owner
+ lifecycle entry method（含 descriptor）
+ sensitive sink callsite
+ authorization-distinct path variant
```

Gold positive 還必須同時支持四項 predicate：

| Predicate | 問題 | 工具 trace 能否單獨回答 |
| --- | --- | --- |
| R — External reachability | 威脅模型中的第三方 app 是否真的可到達該 component/entry | 不能；需合併 Manifest、target SDK、permission/protection level、alias/provider/Binder semantics |
| I — Attacker-controlled input influence | 外部 Intent/Bundle/URI/Binder/Provider input 是否影響敏感效果 | FlowDroid/Mariana Trench 可提供強 candidate evidence，但 coverage limitation 仍須保留 |
| S — Sensitive effect reachability | entry 是否沿具體 chain 到達 sensitive sink/effect | 深度 call/data-flow tool 可提供強 candidate evidence；未找到 path 不等於不可達 |
| A — Authorization failure | 敏感效果前是否缺少有效且不可繞過的 authorization guard | 一般 scanner finding 或 taint trace不能單獨回答；需 guard presence、location、dominance、branch coverage 與 caller semantics |

因此，一個工具即使輸出漂亮的 source-to-sink trace，最多直接改善 I/S evidence；它不會自動完成 R/A，也不會自動形成 Gold。

### 2.2 現有程式已經有什麼

- [`androguard_analyzer.py`](../../app/extractors/androguard_analyzer.py) 使用 Androguard 解析 APK、Manifest components、intent filters、component permissions、Provider read/write permissions、`grantUriPermissions`，並建立 DEX analysis。
- [`sensitive_api_callers.py`](../../app/extractors/sensitive_api_callers.py) 走訪 Androguard method XREF，輸出 caller class/method/descriptor、callee API 與 call offset；程式本身已明確揭露 reflection、native、runtime-loaded code 與 unresolved dispatch 不在完整 coverage 內。
- [`parse_manifest.py`](../../app/tools/parse_manifest.py) 產生 `filter_rows` 與 `resolution_rows`，但目前的 `resolution_rows` 是 Manifest-only 1:1 candidates，caller 是 `<UNKNOWN>`，不是已證實的 bytecode path。
- [`canonical_dataset_pilot.py`](../../app/tools/canonical_dataset_pilot.py) 已把 canonical SHA-256 membership、逐 APK parse status、component evidence、Manifest-only path candidates 與 sensitive caller evidence串成可稽核 pilot artifacts。

300-APK pilot 的 [`summary.json`](../../output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/summary.json) 顯示：

- 300 筆全部通過 SHA-256 verification，297 筆解析成功；
- 2,338 筆 Manifest resolution candidates；
- 28,153 個 distinct sensitive API callers；
- 只有 235 個 callers 可直接對到 lifecycle entry；
- 27,918 個 callers 尚無 direct entry link；
- attacker input controllability 與 runtime authorization guard 對全部 28,153 callers 仍是 unknown。

這個數據指出採用現成工具的優先順序：**不是再找一套會列出 exported component 的報告，而是補跨方法 entry/input-to-sink evidence，並保留 guard semantics 的未知性。**

## 三、MobSF：可直接用到哪一層

### 3.1 能力與自動化介面

MobSF 官方把產品定位為 Android/iOS/Windows 的 security research platform，可做 static/dynamic analysis，並以 REST API/CLI 接入 CI/CD。官方 README 提供 Docker quick start；截至查核日，GitHub releases 的 latest 為 **v4.5.2（2026-08-10）**。[官方 v4.5.2 release](https://github.com/MobSF/Mobile-Security-Framework-MobSF/releases/tag/v4.5.2)

官方 API 文件/模板列有下列靜態掃描流程：

```text
POST /api/v1/upload
POST /api/v1/scan
POST /api/v1/scan_status
POST /api/v1/report_json
POST /api/v1/download_pdf
```

認證 header 可使用 `Authorization: <api_key>` 或 `X-Mobsf-Api-Key: <api_key>`。官方設定另支援 `MOBSF_API_ONLY=1`、自訂 API key、rate limit 與 asynchronous analysis。[官方 API template](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/templates/general/apidocs.html)；[官方 configuration](https://github.com/MobSF/docs/blob/master/configurations.md)；[API-only source](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/settings.py)

MobSF 的 Android static model 明確保存 SHA-256、package、main activity、activities/receivers/providers/services、exported activities、target/min/max SDK、permissions、Manifest analysis、code analysis、Android API、permission mapping、exported counts、Quark findings、network security、secrets 與 SBOM 等資料。[官方 `StaticAnalyzerAndroid` model](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/models.py)

### 3.2 建議重用的 MobSF layers

| MobSF layer | 在本 repo 的合理用途 | 匯入狀態 |
| --- | --- | --- |
| APK metadata/hash | 以 MobSF SHA-256/package/SDK 與 canonical/current parser 做 consistency check | metadata/cross-check；canonical membership 仍以本 repo CSV 為準 |
| Manifest/component inventory | 第二解析器 cross-check；找出 component/permission/SDK 語意差異與 parser regression | candidate evidence，不直接產生 label |
| Decompiled source/smali/files | 提供 reviewer drill-down、定位 guard/sink 周邊程式碼 | evidence artifact；須保存 tool version/config/hash |
| Manifest/code findings | 擴充候選抽樣、weak labeling function、error analysis | `weak evidence`／LF vote；必須允許 abstain |
| Permission mapping/API inventory | 補 candidate prioritization 與 sensitive API coverage audit | feature/evidence candidate；不得把「有 permission/API」當漏洞 |
| REST/API queue | 大批量 upload → scan → status → JSON report orchestration | 可直接採用，但要有 timeout、retry、per-APK status 與 schema adapter |
| Dynamic analyzer/Frida/API monitor | 後續針對少量 Gold/challenge cases 做 runtime corroboration | 不進第一個 PoC；動態沒觸發不等於安全 |

### 3.3 MobSF 不能替代什麼

1. **不能替代 concrete component-path identity。** MobSF model 有 component lists、exported count 與 findings，但這不等於本 repo 要求的 `Manifest component + resolved owner + lifecycle entry + sink callsite + authz-distinct path`。
2. **不能單獨判斷 attacker influence。** 一個 code/API finding 或 sensitive API 出現，通常沒有證明外部 input 真的沿該 path 影響 sink。
3. **不能單獨判斷 guard effectiveness。** 報告看到 permission/check 只表示 guard presence candidate；看不到 check 也可能是解析、decompilation、reflection、native 或 path coverage 缺口。
4. **不能把 score/finding 當 Gold。** MobSF 的規則與資料欄位是通用 mobile security assessment taxonomy，不是指定 reviewer 依本專題 R/I/S/A 威脅模型作出的人工判定。
5. **不能把 malware verdict 當 authz label。** MobSF 的 malware/domain/Quark/permission signals 與 MalDroid family 一樣，只能作 metadata、subgroup analysis 或 candidate evidence。

### 3.4 最安全的整合形狀

```text
canonical CSV + SHA-256 verified APK
                |
                +--> existing Androguard extractor --> current evidence JSONL
                |
                +--> version-pinned MobSF container/service
                         upload -> scan/status -> report_json
                                      |
                                      v
                              mobsf_raw/<sha256>/...
                                      |
                              thin schema adapter
                                      |
                                      v
                         tool_evidence (not labels)
```

採 sidecar 有三個好處：不需把 MobSF 的 Django/database/internal modules copy 進 production package；REST boundary 容易 pin version 與保存 raw report；也能讓 GPL 邊界較清楚。這不是正式法律結論，若要發佈整合產品仍需做 dependency/license review。

### 3.5 MobSF deployment caveats

- **必須 pin image tag/digest，不可用漂移的 `latest` 做實驗依據。** 保存 MobSF version、container digest、config digest、API schema sample 與 scan logs。
- **惡意 APK 是不可信輸入。** 使用隔離 VM/container、非公開 bind address、最小權限、唯讀 input mount、獨立 output volume；不要把公開 MobSF instance 或 API key 暴露到不可信網路。
- 官方動態分析文件目前寫明 Android 4.1–11、最高 API 30，對新 Android platform semantics 不應假設完整。[官方 develop docs](https://github.com/MobSF/docs/blob/master/develop.md)
- MobSF 自身也可能有 security advisories；例如 v4.4.4 的 Manifest stored XSS 在 v4.4.5 修補。掃描器處理的正是不可信檔案，所以安全更新是 deployment gate，不是一般維護細節。[官方 GHSA-8hf7-h89p-3pqj](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-8hf7-h89p-3pqj)

## 四、其他候選工具

### 4.1 Androguard — 繼續採用的低階分析底座

**官方定位與輸出**

Androguard 是 Python-based Android reverse engineering/pentesting toolkit，支援 APK、DEX/ODEX、binary XML、resources、disassembly、basic decompiler 與 SQLite session。官方 analysis API 的 `MethodAnalysis` 保存 caller/callee XREF 與 bytecode offset；CLI 也提供 call graph command。[官方 repo](https://github.com/androguard/androguard)；[官方 analysis source](https://github.com/androguard/androguard/blob/master/androguard/core/analysis/analysis.py)

**對本 repo 的價值**

- 已經直接嵌入 Python pipeline，能保持本 repo 自己的 dataclass/schema/error status；
- Manifest namespace attributes、component identity、intent filters、Provider permission 與 call offsets 都能細粒度保存；
- 適合做 deterministic raw evidence extractor 與其他工具的 normalization anchor；
- 比引入 MobSF 內部 Django model 更接近現有 production boundary。

**不適合直接宣稱的能力**

- 基本 XREF/call graph 不是 path-sensitive、taint-aware authorization analysis；
- caller → callee edge 不會自動證明 lifecycle entry 可達、外部 input influence 或 runtime guard dominance；
- `get_xref_to()` 走訪完成也不是 reflection/native/runtime-loaded code 的 soundness guarantee。

**維護 caveat**

官方 README 警告 4.x 與 2019 年的 3.3.5 差異大、部分功能已移除；並明示 ReadTheDocs 有過時資訊，GitHub Pages 才是較新文件。截至查核日 releases 列出 v4.1.4，且 repo 另提示 `ng` branch。故 `requirements.txt` 現行 `androguard>=4.0` 對可重現實驗太寬，後續 integration 應改為經測試的 exact version/lock；這是未來 implementation 建議，本研究筆記不修改 dependency。[官方 README/releases](https://github.com/androguard/androguard/releases)

### 4.2 FlowDroid — 第一順位 deep-path PoC

**官方定位與介面**

FlowDroid 是 Android/Java static data-flow tracker，提供 CLI 與 Java library；使用者自訂 sources/sinks，CLI 接受 APK、Android SDK platforms 與 source/sink definition。它支援 Windows、macOS、Linux，並提供 callback/data-flow/result collection timeouts。Java library 以 `InfoflowResults` 取得結果。[官方 repo/usage](https://github.com/secure-software-engineering/FlowDroid)

原始論文描述它為 lifecycle-aware、context/flow/field/object-sensitive Android taint analysis；這說明它比目前一階 XREF 更適合補跨方法 input-to-sink evidence，但論文 benchmark 表現不能直接外推成本專題真實 APK 的 Gold accuracy。[PLDI 2014 論文官方機構典藏](https://orbilu.uni.lu/handle/10993/20223)

截至查核日 official latest release 為 **2.15.1**，官方 `develop` POM 已是 2.16.0-SNAPSHOT；PoC 應使用 release artifact，而非漂移的 snapshot。[官方 releases](https://github.com/secure-software-engineering/FlowDroid/releases)；[官方 POM](https://github.com/secure-software-engineering/FlowDroid/blob/develop/pom.xml)

**如何對齊本專題**

- sources：`Activity.getIntent()`、Intent/Bundle getters、receiver Intent、Service command/bind arguments、Provider URI/operation arguments、Binder parameters等外部 input surfaces；
- sinks：沿用並校正本 repo sensitive API taxonomy，避免把 `Cursor.getString`、generic file I/O 等缺乏語境的 call 一律當 confirmed sensitive effect；
- output：使用 XML/result API 保存 source、sink、path statements、entry point、analysis termination/timeout；再 normalize 成 `candidate_id`/`path_id` evidence；
- link：以 APK SHA-256 + class/method descriptor + sink/source statement location 對回 Manifest component，不用 filename/MD5 當 canonical identity。

FlowDroid maintainer也明確說明，source/sink 定義就是 analysis problem definition；做 injection/vulnerability analysis 時可把 incoming intents 或 Internet data 設為 source，而不是只用 privacy leak 的預設 definitions。[官方 issue 中 maintainer 說明](https://github.com/secure-software-engineering/FlowDroid/issues/152)

**限制與標籤邊界**

- FlowDroid trace 可強化 I/S，但不自動證明 Manifest external reachability R。
- 「trace 穿過/未穿過 permission check」不等於 guard effective/ineffective；要另做 guard model、dominance/branch audit與人工 review。
- timeout 後回傳 partial results 必須標 `analysis_timeout/partial`；沒結果不能標 negative。
- path reconstruction mode 本身也可能有 precision/recall/bug trade-off，應先在 toy truth suite 固定設定，而不是以單一模式當真值。[官方 issue #764](https://github.com/secure-software-engineering/FlowDroid/issues/764)

### 4.3 Mariana Trench — 高度可配置的第二 deep-taint 候選

**官方定位與介面**

Mariana Trench 是 Meta 的 Android security-focused static analysis platform，直接分析 APK Dalvik bytecode。它以 rules、model generators、lifecycle models 與 system jars 定義 source/sink/propagation；輸出 run metadata 與分片 JSON method data-flow specifications，再由 SAPP post-process 與瀏覽 trace。[官方 repo/getting started](https://github.com/facebook/mariana-trench)；[官方 configuration](https://github.com/facebook/mariana-trench/blob/main/documentation/website/documentation/configuration.md)；[官方 SAPP](https://github.com/facebook/sapp)

官方 sample 正好展示 `Activity.getIntent` 經多層 calls 流入 `ProcessBuilder` 的 RCE trace，包含 source trace、trace root 與 sink trace；這與本專題要補的 attacker-input influence + multi-method sensitive-sink linkage 很接近。[官方 README example](https://github.com/facebook/mariana-trench)

截至查核日 PyPI latest 為 **1.0.8（2026-03-25）**；官方提供 source distribution、manylinux1 x86-64 wheel 與 macOS x86-64 wheel，未列 Windows wheel。[官方 PyPI release metadata](https://pypi.org/project/mariana-trench/)

**適用方式**

- 若 FlowDroid 無法穩定產生 path evidence，或需要 model-generator/rule 更強的可配置性，使用同一套 toy + real pilot suite 評估 Mariana Trench；
- 可把既有 sensitive API specs 轉成 sink models，把 Android input APIs/component lifecycle 建成 source/lifecycle models；
- 匯入 raw JSON/SAPP trace 時保留 source/sink kind、callable、positions、trace length、config/rule/model digests與 limitation codes。

**限制與成本**

- 官方文件直接提醒需要投入大量時間撰寫 model generators；Meta 內部甚至由專職 security engineers 長期維護 rules/models。這不是安裝後即可自動符合本專題語意的 scanner。
- Linux VM/container 是目前最實際部署路徑；不要假設 Windows `.venv` 可以直接安裝官方 wheel。
- trace 的有無高度受 rules/models/lifecycles/system jars/heuristics 影響；仍不能作 Gold 或「未發現即安全」。

### 4.4 Amandroid／Argus-SAF — 概念合適但暫不優先

Argus-SAF 官方 repo 包含 Amandroid module，提供 Android resource parsers、information collector、decompiler、environment method builder 與 flow analysis，能以 library dependency 或 fat-JAR CLI 使用。Amandroid 論文重點是 Android inter-component data-flow analysis，涵蓋 ICC/RPC/static-field 等 component間資料流。[官方 repo](https://github.com/arguslab/Argus-SAF)；[官方 Amandroid technical report](https://www.arguslab.org/documents/tech_reports/2017/amandroid_fgwei_2017.pdf)

它在概念上最接近 component/ICC，但目前不列第一順位：

- 官方 README 的 CLI requirement 仍是 Java 10；
- official latest release v3.1.3 自稱 V4.0.0 前的 pre-release；
- 官方 GitHub organization 顯示 Argus-SAF 最後更新為 2023-07-05；
- Scala/SBT/Jawa/legacy dependency 與輸出 adapter 的維護成本較高。

如果 FlowDroid 與 Mariana Trench 都在本專題的 Service/Binder/Provider/ICC cases 出現不可接受的 coverage，才應以同一 acceptance suite 做 Amandroid spike；不應因論文能力敘述直接承諾 production adoption。[官方 releases](https://github.com/arguslab/Argus-SAF/releases)

## 五、能力、整合與授權總表

| 工具 | 最適合重用的層 | Automation/output | License | 截至 2026-08-25 的維護訊號 | 本專題建議 |
| --- | --- | --- | --- | --- | --- |
| MobSF 4.5.2 | 一站式 static/dynamic triage、parser/decompiler cross-check、報告瀏覽 | REST upload/scan/status/JSON/PDF、Docker、DB-backed report | GPL-3.0 | 2026-08-10 release，仍有 security hotfix/active commits | 可採獨立 sidecar；pin tag + image digest；不 fork、不當 detector/Gold |
| Androguard 4.x | APK/AXML/DEX/XREF/raw evidence | Python API、CLI、call graph/session | Apache-2.0 | v4.1.4；官方警告 docs/API drift並提示 `ng` | 繼續採用；pin exact tested version |
| FlowDroid 2.15.1 | lifecycle-aware interprocedural taint/path | CLI XML、Java `InfoflowResults`、timeouts | LGPL-2.1 | 2026 release；develop 2.16 snapshot | 第一 deep-path PoC；自訂 input sources/sinks |
| Mariana Trench 1.0.8 | configurable security taint traces | CLI、sharded JSON models/metadata、SAPP | MIT | 2026 PyPI release；Linux/mac x86-64 artifacts | 第二候選/交叉驗證；在 Linux 隔離環境跑 |
| Amandroid/Argus-SAF 3.1.3 | ICC/inter-component data flow research | Scala library、fat JAR CLI | Apache-2.0 | repo last updated 2023、Java 10、pre-v4 release | 暫不採用；只在前兩者 coverage 失敗時 spike |

### 5.1 License caveats

- **MobSF：GPL-3.0。** 直接修改/散布 MobSF 或形成 derivative work 可能觸發 GPL source/notice obligations。優先採 unchanged、version-pinned container，以 REST boundary 與本 repo 分離；若要對外散布整合映像或改 MobSF 原始碼，先做正式法律/授權 review。[MobSF LICENSE](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/LICENSE)
- **Androguard：Apache-2.0。** 官方 README 直接列出 Androguard 與 DAD 的 Apache-2.0 terms；一般允許使用/修改/散布，但需保留 license/notice 等條件，同時檢查 bundled/optional dependencies。[Androguard official README license section](https://github.com/androguard/androguard#licenses)
- **FlowDroid：LGPL-2.1。** 官方說明可用於 closed-source project，但修改/延伸 FlowDroid 本身須依 LGPL 提供相應變更；CLI subprocess boundary 比直接 fork/merge code 更容易管理。[FlowDroid LICENSE](https://github.com/secure-software-engineering/FlowDroid/blob/develop/LICENSE)
- **Mariana Trench：MIT。** 保留 copyright/license notice；另需稽核 Redex/SAPP/system jars 等實際部署依賴。[Mariana Trench LICENSE](https://github.com/facebook/mariana-trench/blob/main/LICENSE)
- **Argus-SAF：Apache-2.0。** 保留 license/notice，並稽核 Scala/SBT/packaged binaries 的 transitive dependencies。[Argus-SAF LICENSE](https://github.com/arguslab/Argus-SAF/blob/master/LICENSE)

以上是工程風險分類，不是法律意見。真正採用前要針對「如何連結、是否修改、是否散布、是否提供網路服務、是否打包第三方 binary」建立 dependency/license inventory。

## 六、Build vs Adopt 決策

### 6.1 應採用（adopt）的部分

- APK/Manifest/DEX parsing 與 XREF：Androguard；
- secondary scanner/decompiler/report/API orchestration：MobSF sidecar（若 PoC 證明提供非重複價值）；
- interprocedural taint/path engine：先 FlowDroid，必要時 Mariana Trench；
- trace browsing：MobSF UI 或 Mariana Trench + SAPP 只作人工 review 輔助；
- standard test corpora/tool regression：可參考各工具官方 benchmark，但本專題仍需自己的 toy authorization truth suite。

### 6.2 必須自行建置（build）的部分

- `tool_attempt`、`candidate`、`concrete_path` 三層 record contract；
- SHA-256-first canonical membership 與 source verification；
- Manifest alias/provider/permission/URI grant/Binder semantics normalization；
- 不同工具 class/method/descriptor/callsite 的 stable identity mapping；
- R/I/S/A predicate evidence與 `confirmed/refuted/unknown`；
- guard detection/effectiveness/dominance 與 limitation codes；
- weak LFs、abstention、append-only Golden review；
- anti-leakage feature profile、package/lineage isolation、Golden evaluation 與 SLB revision provenance；
- tool version/config/rule/model/output hashes、timeout/partial/failed status。

### 6.3 明確不做

- 不把 MobSF fork 成本專題 monolith；
- 不把 MobSF score、FlowDroid leak、Mariana issue 或 Amandroid flow 直接寫入 `gold_authz_label`；
- 不用任何工具的「zero findings」填成 negative；
- 不一次導入四套 deep analyzers；
- 不先跑完整 25,358 APK deep analysis；
- 不讓 external tool output 覆寫 `observed_authz_label`、`gold_authz_label` 或 `revised_authz_label`。

## 七、最小 PoC 與 acceptance criteria

建議把 PoC 分成兩條彼此可停止的 track。兩者都只讀 APK，輸出放在獨立實驗目錄，不改 production extractor/schema。

### Track A：MobSF enrichment sidecar（2–3 天工程 spike）

**輸入**

- 與 v1 scope 相符的 hand-authored toy APK（見下節 cases；Provider/Binder deferred cases 不作 v1 gate）；
- 從已驗 SHA-256 的 300-APK pilot 固定抽 6 個 real APK，low／medium／high complexity 各一組 matched pair；
- 固定 MobSF version/image digest 與 config。

**輸出**

```text
output/framework_poc/<run_id>/
  run_metadata.json
  attempts.csv
  mobsf_raw/<sha256>/upload.json
  mobsf_raw/<sha256>/scan_status.json
  mobsf_raw/<sha256>/report.json
  normalized/mobsf_evidence.jsonl
  comparison/parser_diff.jsonl
  summary.json
```

**Acceptance**

1. 每筆以 canonical SHA-256 連結；MobSF report SHA-256 必須與 input 一致，否則 hard fail。
2. 每個固定 toy／real APK 都留下 success/partial/timeout/failed，不得 silent drop。
3. normalization 不產生 label；每筆 evidence 保留 raw report reference、MobSF version、image digest、rule/config digest。
4. toy components 的 name/type/exported/permission/provider read-write permission 能與 truth fixture 對齊；差異進 `parser_diff`，不自動選一邊為真。
5. 兩次相同設定執行後，normalized stable identities 一致；不穩定欄位明確排除或 canonicalize。
6. MobSF 至少提供一種目前 pipeline 沒有、且 reviewer 實際可用的 evidence（例如可定位 decompiled code、獨立 manifest discrepancy 或 useful code finding）。若只重複 Androguard component lists，停止 integration。
7. 任何 MobSF finding/score 都只能落在 `tool_evidence`/LF candidate 欄位；測試應拒絕寫入三層 label 欄位。

### Track B：FlowDroid deep-path bridge（第一順位，3–5 天工程 spike）

若 Track B 在安裝/coverage 上失敗，再用相同 fixture/config contract 替換為 Mariana Trench；不要同時改兩套 source/sink semantics。

**Toy acceptance cases**

| Case | 程式語意 | 預期 evidence/label boundary |
| --- | --- | --- |
| T1 | exported Activity；`getIntent` extra 經 2+ methods 流入明確 sink；無 guard | 必須找到 multi-method I/S trace；A 仍由 guard analysis/review 決定，tool 不直接寫 positive |
| T2 | 同 T1，但 component 受有效 signature permission 保護 | taint trace可以存在；R 應由 Manifest/permission evidence refute，不可因 trace 標 positive |
| T3 | exported entry；runtime UID/signature/permission guard 支配 sink | 可有 input/sink candidates；A 需 guard evidence refute，deep tool finding不得蓋過它 |
| T4 | guard 只保護一個 branch，另一個 attacker-controlled branch可繞過 | path variants 必須分開；若 tool 合併，標 limitation/unknown，不可假裝 guard 全域有效 |
| T5 | exported component 但 entry 無法到達任何 configured sink | 不得虛構 concrete path；「未找到」本身仍不是 Gold negative |
| T6 | app 內其他 class 有 sink，但 exported entry 到不了它 | 不得只因全 APK 出現 sink 就建立 entry-to-sink path |
| T7 | exported Provider，read/write/path permission 與 URI grant 語意不同 | query/openFile/write operations 分列；unsupported semantics 明確 unknown |
| T8 | Service 同時有 `onStartCommand` 與 `onBind`/returned Binder methods | entry methods/transactions 不得合併成一列 |

FlowDroid v1 的必要範圍只含 Activity、Receiver 與 started-Service 的 Intent／Bundle／URI source 到 Tier-A sensitive effect；T7 Provider 與 T8 Binder 部分保留為 deferred regression cases，不作 v1 安裝或整合成敗條件。

**Real APK sample**

- 固定 6 APK；以 low／medium／high complexity 三組 matched pairs 比較 baseline manual review 與 tool-assisted review，每 APK 固定 2 個 review units；
- 不用 malware family 選擇或判定 authorization truth，只作 subgroup metadata；
- 每 APK 設 callback/callgraph/data-flow/result timeout，並記錄各階段 termination reason。

**Acceptance**

1. 所有納入 v1 scope 的 toy APK 完成 analysis attempt；預期 multi-method trace 的 cases 能產生可稽核 source/path/sink evidence。
2. T2/T3 不得被 adapter 直接轉成 positive；T5/T6 不得因 APK-wide sink inventory 產生假的 concrete entry-to-sink path。
3. normalized path 至少有 APK SHA-256、Manifest component identity、resolved owner、entry method+descriptor、source、sink method、path statements；工具沒有 call offset時必須填 `callsite_location_unavailable`，不得編造 offset。
4. 同一 entry/sink 的 guard-distinct/provider-operation/Binder-entry variants 不可無聲合併；工具無法區分時輸出 candidate + limitation，而不是 concrete path。
5. 相同 binary/config 連跑兩次，normalized `candidate_id`/`path_id` 與 termination status 可重現。
6. 6 個 real APK 至少 5 個在預設 per-stage timeout 內完成；未達標先調整 scope/performance，不外推到 50/300/25,358 APK。此門檻是 PoC go/no-go threshold，不是預先宣稱的工具能力。
7. 相較目前 direct lifecycle link，PoC 至少在一個 real APK 上新增「跨方法 entry/input-to-sink trace」；若完全沒有新增 evidence，停止 integration並檢查 source/sink/lifecycle models。
8. 對每筆結果保存 tool release checksum、JDK/Android platforms、source/sink definitions、CLI args、stdout/stderr、raw output hash、duration、peak memory（可取得時）與 status。
9. adapter schema 必須把 `no_result`、`partial`、`timeout`、`analysis_failed` 分開；任何一種都不得默認為 negative。
10. PoC 最後只回答「這個 engine 是否提供值得匯入的 evidence、是否降低 reviewer 人工時間，以及成本是否可接受」，不回答「模型 accuracy 已驗證」。正式 accuracy 要等 50 APK Golden Set、configuration lock 與 3-seed evaluation。

## 八、執行順序與決策門

```text
Step 0  Freeze v1 toy truth + 6 real APK membership + SHA-256
  |
Step 1  FlowDroid CLI PoC（固定 release/config/timeouts）
  |-- pass --> 寫 thin raw-output adapter contract，再擴到 bounded deep subset
  |-- fail on install/coverage --> 用同一 suite 試 Mariana Trench
  |-- both fail --> 才評估 Amandroid spike或縮成 Manifest + caller evidence研究
  |
Step 2  MobSF sidecar PoC（可與 Step 1 分開排程）
  |-- produces unique reviewer value --> 保留 optional enrichment service
  |-- duplicates Androguard --> 不整合，只保留人工工具
  |
Step 3  Guard analyzer + R/I/S/A evidence contract
  |
Step 4  Gold review / weak LFs / SLB（external tool output仍不是 Gold）
```

**停止條件**

- 安裝/維護成本大於新增 evidence；
- real APK 在 bounded timeout 下 completion < 80%；
- 無法 stable map 回 component/path identity；
- raw output/schema 在固定 release 下仍不穩定且無法 version adapter；
- 只增加 generic findings，沒有跨方法 I/S evidence或 reviewer utility；
- license/deployment boundary 不符合專題發佈方式；
- 團隊開始把 tool finding 當 Gold、把 zero finding 當 negative——此時應先修 evidence contract，而不是擴大 corpus。

## 九、來源索引（primary sources only）

### MobSF

- [Official repository, README and GPL-3.0](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Official v4.5.2 release, 2026-08-10](https://github.com/MobSF/Mobile-Security-Framework-MobSF/releases/tag/v4.5.2)
- [Official REST API documentation template](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/templates/general/apidocs.html)
- [Official API routes](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/urls.py)
- [Official Android static-analysis data model](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/models.py)
- [Official configuration reference](https://github.com/MobSF/docs/blob/master/configurations.md)
- [Official installation/dynamic platform notes](https://github.com/MobSF/docs/blob/master/develop.md)
- [Official license](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/LICENSE)
- [Official security advisory GHSA-8hf7-h89p-3pqj](https://github.com/MobSF/Mobile-Security-Framework-MobSF/security/advisories/GHSA-8hf7-h89p-3pqj)

### Androguard

- [Official repository and README](https://github.com/androguard/androguard)
- [Official releases](https://github.com/androguard/androguard/releases)
- [Official analysis/XREF implementation](https://github.com/androguard/androguard/blob/master/androguard/core/analysis/analysis.py)
- [Official README license section](https://github.com/androguard/androguard#licenses)

### FlowDroid

- [Official repository, CLI/library usage, timeouts and license explanation](https://github.com/secure-software-engineering/FlowDroid)
- [Official releases](https://github.com/secure-software-engineering/FlowDroid/releases)
- [Official build metadata and LGPL-2.1 declaration](https://github.com/secure-software-engineering/FlowDroid/blob/develop/pom.xml)
- [Maintainer explanation of use-case-specific source/sink definitions](https://github.com/secure-software-engineering/FlowDroid/issues/152)
- [PLDI 2014 paper, University of Luxembourg repository](https://orbilu.uni.lu/handle/10993/20223)
- [Official license file](https://github.com/secure-software-engineering/FlowDroid/blob/develop/LICENSE)

### Mariana Trench

- [Official repository and getting-started trace](https://github.com/facebook/mariana-trench)
- [Official analysis configuration and output description](https://github.com/facebook/mariana-trench/blob/main/documentation/website/documentation/configuration.md)
- [Official PyPI release/artifact metadata](https://pypi.org/project/mariana-trench/)
- [Official SAPP post-processor](https://github.com/facebook/sapp)
- [Official license](https://github.com/facebook/mariana-trench/blob/main/LICENSE)

### Amandroid／Argus-SAF

- [Official Argus-SAF repository](https://github.com/arguslab/Argus-SAF)
- [Official releases](https://github.com/arguslab/Argus-SAF/releases)
- [Official Amandroid technical report](https://www.arguslab.org/documents/tech_reports/2017/amandroid_fgwei_2017.pdf)
- [Official license](https://github.com/arguslab/Argus-SAF/blob/master/LICENSE)
