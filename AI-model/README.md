後端呼叫格式
python -m app.main \
  --in ./input/request.json \
  --out ./output/report.json \
  --artifacts ./artifacts

schema validation
python -m app.schema_validation --type request --in ./input/request.json
python -m app.schema_validation --type report   --in ./output/report.json

canonical dataset 唯讀 pilot consumer

```powershell
.\.venv\Scripts\python.exe -m app.tools.canonical_dataset_pilot `
  --canonical-csv <canonical_balanced_dataset.csv> `
  --output-dir output\canonical_pilot\pilot_300_six_strata_seed_20260823_v3 `
  --sample-size 300 --seed 20260823
```

六層各 50 筆抽樣、SHA-256 驗證、component/path 與 sensitive API caller
證據語意及輸出檔案說明：
[`docs/canonical_dataset_pilot.md`](docs/canonical_dataset_pilot.md)
