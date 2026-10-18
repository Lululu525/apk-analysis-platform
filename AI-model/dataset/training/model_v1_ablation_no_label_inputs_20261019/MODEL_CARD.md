# Component risk ablation — no direct label inputs

## 目的

這是研究對照模型，不是正式部署模型。它使用與 `model_v1` 相同的 256 筆
component-level weak-label rows，但排除直接或近乎直接揭露標籤的三個輸入：

- `exported`
- `protected`
- `permission`

標籤仍是 `exported == true and protected == false`，因此這個實驗只能衡量其餘
manifest 特徵重建弱標籤的能力，仍不能代表真實漏洞偵測效果。

## 結果

| Split | Accuracy | Positive-class F1 | Macro F1 | Confusion matrix |
|---|---:|---:|---:|---|
| Train | 0.913 | 0.935 | 0.903 | `[[53,4],[12,115]]` |
| Validation | 0.903 | 0.933 | 0.878 | `[[7,1],[2,21]]` |
| Test | 0.854 | 0.893 | 0.831 | `[[10,1],[5,25]]` |

原始模型 test F1=1.0；移除三個洩漏／近洩漏欄位後，positive-class test F1
降為 0.893，macro F1 為 0.831。剩餘特徵仍可透過元件類型和 Intent action
學到資料集中的相關模式，但需要獨立人工 Gold label 才能測量實際泛化能力。

## 重現指令

```bash
python AI-model/app/ml/trainer.py \
  --data AI-model/dataset/training/filter_rows.jsonl \
  --out-dir AI-model/dataset/training/model_v1_ablation_no_label_inputs_20261019 \
  --exclude-feature exported \
  --exclude-feature protected \
  --exclude-feature permission
```
