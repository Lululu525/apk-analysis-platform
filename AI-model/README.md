後端呼叫格式
python -m app.main \
  --in ./input/request.json \
  --out ./output/report.json \
  --artifacts ./artifacts

schema validation
python -m app.schema_validation --type request --in ./input/request.json
python -m app.schema_validation --type report   --in ./output/report.json