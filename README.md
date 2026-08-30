# VerifyAI

AI-assisted document verification for invoices, purchase orders, and contracts. VerifyAI combines upload workflows, structured extraction, comparison checks, risk scoring, audit history, and analytics in a responsive SaaS dashboard.

## Run locally

### Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

Requires Node.js 18+.

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The API is available at `http://localhost:8000/docs`.

The backend seeds a small set of realistic demo invoices, purchase orders, and contracts on first startup. Uploads are stored in `uploads/`; SQLite data is stored in `verifyai.db`.

## OCR prerequisites

PDF text extraction uses PyMuPDF. JPG, JPEG, and PNG extraction uses `pytesseract`, which also requires the Tesseract OCR executable installed and available on `PATH`. The API returns a clear `503` response if the image OCR runtime is not available.
