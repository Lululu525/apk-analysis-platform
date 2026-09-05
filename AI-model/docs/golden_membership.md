# 固定 50-APK Golden membership

本次 `golden-50-v1` 已凍結 **50 個唯一 APK／50 個 package**，涵蓋 K=17 的全部群集。Membership 只定義未來人工 Golden review 的 APK 範圍；沒有產生 Gold labels、component review rows、weak labels 或訓練結果。

## 檔案與執行

| 檔案 | 用途 |
|---|---|
| `app/tools/golden_membership.py` | 最小 CLI：載入母體、驗證 canonical provenance、clustering、sensitivity、凍結 |
| `tests/test_golden_membership.py` | feature allowlist、去重、lineage、補額、determinism、來源完整性與禁止覆蓋 |
| `dataset/authz_v2/golden_50_membership.csv` | 50 個 APK 的正式 membership，含 source/version/group/selection provenance |
| `dataset/authz_v2/golden_50_selection_metadata.json` | 候選與 feature fingerprints、scaler、各 K 結果、完整 candidate/group registry、sibling exclusions |

```powershell
.\.venv\Scripts\python.exe -m app.tools.golden_membership `
  --pilot-csv output/canonical_pilot/pilot_300_six_strata_seed_20260823_v3/sample_results.csv `
  --output-dir dataset/authz_v2
```

**此指令已執行；再次指向既有輸出會拒絕覆蓋。** 任一正式產物存在即停止，包括僅存一個檔案的中斷情況。不得因 MobSF／FlowDroid failure、找不到 path、unknown 或結果不理想而替換 APK。未來需要修正時須另立明確版本與理由，不能默默改動 v1。

## 母體、特徵與設定

唯一候選輸入為指定 pilot CSV，canonical reference 由同目錄 `run_metadata.json` 取得，並核對 canonical CSV SHA-256。300 筆中只有 297 筆 parse-success；另外 3 筆 failed rows 的既有 CSV 多餘欄位已記錄於 metadata，不用其 features。成功 rows 的欄位數、identity、數值、package 與 canonical row reference 均嚴格驗證。

依 SHA-256 去重後仍為 297 個 APK（dedupe=0），共 268 個 package。凍結前重新讀取 **297 個來源檔案並驗證 SHA-256**，不掃描實體目錄定義 membership，也不改寫原 APK。

固定十維 features：

| Feature | pilot 欄位／公式 |
|---|---|
| `log1p(activity_count)` | `log1p(component_activity_count)` |
| `log1p(service_count)` | `log1p(component_service_count)` |
| `log1p(provider_count)` | `log1p(component_provider_count)` |
| `log1p(receiver_count)` | `log1p(component_receiver_count)` |
| `log1p(component_evidence_row_count)` | 同名 count 取 log1p |
| `log1p(unique_exported_component_name_count)` | 同名 count 取 log1p，僅為指定的 APK-level coverage aggregate |
| `log1p(sensitive_api_call_site_count)` | 同名 count 取 log1p |
| `log1p(sensitive_api_caller_count)` | 同名 count 取 log1p |
| `direct_component_ratio` | `sensitive_api_direct_component_caller_count / sensitive_api_caller_count` |
| `direct_entry_ratio` | `sensitive_api_direct_entry_caller_count / sensitive_api_caller_count` |

ratio 分母為 0 時設為 0；count 必須為有限非負整數，direct callers 不得多於 distinct callers。只用明確 allowlist 組成數值矩陣，未加入 observed/revised labels、malware family、dataset/source identity、prediction、MobSF finding ID、component-level exported/protected/permission 或 risk_hint。APK SHA/package 僅用於排序、grouping、選樣及稽核，不進 clustering matrix。這些 coverage features 不因本次使用而獲准用於後續 anti-leakage training profile。

StandardScaler：`with_mean=True, with_std=True`。KMeans：K=17、seed=20260823、n_init=50、init=k-means++、algorithm=lloyd、max_iter=300、tol=0.0001；K=15/17/20 用相同 scaler 與參數進行 sensitivity。完整 scaler mean/scale/variance、各 K metrics／selected SHA 清單及 K=17 centers 都保存在 metadata。

## Deterministic 選樣

1. 候選依 SHA-256 排序後 fit；固定數值單執行緒及記錄套件版本。Windows 的 joblib core probe 以暫時 `LOKY_MAX_CPU_COUNT=1` 避開 CP950 subprocess decode，結束後恢復原環境值。
2. Cluster ID 依 standardized centroid 的字典序正規化；同 centroid 以該群最小 SHA 決勝。
3. 每輪先走 package 種類較少的 cluster，再依 cluster ID。先一輪 representative（距 centroid 最近），再 diverse、third（與該群已選 APK 的最小距離最大）。候選都先優先採尚未選到的 package，距離相同以 `SHA256(seed:APK_SHA256)` 升序決勝。
4. 小群集不重複抽取。若三輪未滿 50，從仍有新 package 的群集優先補額；群集依已選數／母體數最小、cluster ID 升序選定，再用 max-min distance 選 `coverage_fill`。

K=17 的群集容量使前三輪最多只能取得 47 個 APK，所以本次為 **17 representative + 16 diverse + 14 third + 3 coverage_fill = 50**。結果有 50 個不同 package，已達 50 APK 的 package uniqueness 上限；此 heuristic 對任意其他母體不宣稱有全域最佳化保證。

重新載入母體、逆序送入 selector 後，50 個 SHA 的順序、feature/config fingerprint 與三組 sensitivity 結果均與凍結結果一致。可重現性以已記錄的 numerical library versions 為範圍；不宣稱跨版本浮點結果一定相同。Freeze timestamp 不納入 membership identity hash。

## Version／lineage 與後續隔離

Canonical version metadata 在入選 APK 中有 48/50 筆可得；另 2 筆以 `unknown-version:<sha256>` 明記，不推測版本。`package_group` 保留 package identity，`lineage_group` 是同 package 或明確 canonical lineage 關係的傳遞閉包。

本次 canonical 沒有明確的跨 package lineage 欄位值，因此 grouping 的已知依據只有 package；不以 certificate 或 malware family 自動推斷 lineage，也不宣稱已排除未知重打包關係。Metadata 保存全部 297 個候選的 group 與是否應因 Golden group 排除於未來訓練。

有 **8 個未入選 APK** 與 Golden APK 同 group，列在 `golden_group_sibling_sha256`。後續 weak-training candidate pool 在目前已知關係下最多為 `297 − 50 − 8 = 239`；此處僅保存隔離資訊，尚未建立或訓練該 pool。新增 lineage 證據只能進一步排除 training siblings，不更換已凍結 Golden APK。

## Sensitivity 與凍結紀錄

| K | APK / package / clusters | 與 K=17 重疊 APK | Jaccard | Silhouette |
|---|---|---:|---:|---:|
| 15 | 50 / 50 / 15 | 39 | 0.639344 | 0.287651 |
| 17 | 50 / 50 / 17 | 50 | 1.000000 | 0.285959 |
| 20 | 50 / 50 / 20 | 27 | 0.369863 | 0.293425 |

Sensitivity 顯示選樣會隨 K 改變；不以 silhouette 或任何 label 改選正式 K。正式 membership 固定 K=17。

- Membership version：`golden-50-v1`
- Freeze timestamp：`2026-09-05T15:39:59.225080+08:00`
- Membership SHA-256：`7382f4d5e0434c8b7b37fa81269f88e32fe5d2fadc119301b56d512f9768f6e4`
- CSV bytes SHA-256：`0d50029142e5ac8ee567fd72a732782723eb1d57588026b0860ea00fb9694ada`
- 候選 SHA 集合 fingerprint：`1633c293523febfac1555c65d17bc22dc6ee89c9a6de48e2aef3bf88b525f88a`

Membership fingerprint 定義為「排序後 50 個 SHA 字串清單」的 canonical JSON SHA-256；CSV fingerprint 另涵蓋 freeze timestamp 與所有欄位。原始 pilot CSV、canonical CSV、feature matrix、config、scaler、generator source 與 runtime version fingerprints 詳見 selection metadata。
