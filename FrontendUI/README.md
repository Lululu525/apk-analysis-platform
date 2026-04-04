# APK Dashboard Final

## 1. Install

```bash
npm install
```

## 2. Configure API

Copy `.env.example` to `.env` and adjust if needed.

```bash
cp .env.example .env
```

Default backend URL:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

## 3. Start frontend

```bash
npm run dev
```

## 4. Backend reminder

Your FastAPI backend should be started on:

```bash
python -m uvicorn apps.api.main:app --reload --host 127.0.0.1 --port 8000
```
