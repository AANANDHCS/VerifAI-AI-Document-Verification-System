from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import json
import re
import uuid
from difflib import SequenceMatcher

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine, desc, inspect, text as sql_text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

try:
    import fitz
except ImportError:
    fitz = None

try:
    from PIL import Image
    import pytesseract
except ImportError:
    Image = None
    pytesseract = None

BASE_DIR = Path(__file__).resolve().parents[2]
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DATABASE_URL = f"sqlite:///{BASE_DIR / 'verifyai.db'}"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}
ALLOWED_CONTENT_TYPES = {"application/pdf", "image/jpeg", "image/png"}
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

class Base(DeclarativeBase):
    pass

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_name: Mapped[str] = mapped_column(String(255))
    document_type: Mapped[str] = mapped_column(String(40))
    vendor: Mapped[str] = mapped_column(String(180), default="Unknown vendor")
    invoice_number: Mapped[str] = mapped_column(String(80), default="")
    po_number: Mapped[str] = mapped_column(String(80), default="")
    invoice_date: Mapped[str] = mapped_column(String(40), default="")
    amount: Mapped[float] = mapped_column(Float, default=0)
    tax_amount: Mapped[float] = mapped_column(Float, default=0)
    score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(40), default="PENDING REVIEW")
    risk_level: Mapped[str] = mapped_column(String(30), default="MEDIUM")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    extracted_data: Mapped[str] = mapped_column(Text, default="{}")
    mismatch_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), default="info")
    document_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Comparison(Base):
    __tablename__ = "comparisons"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    left_document_id: Mapped[int] = mapped_column(Integer)
    right_document_id: Mapped[int] = mapped_column(Integer)
    similarity_score: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[str] = mapped_column(String(40), default="REVIEW")
    findings: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class AppSettings(Base):
    __tablename__ = "app_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    profile_name: Mapped[str] = mapped_column(String(120), default="Alex Morgan")
    profile_email: Mapped[str] = mapped_column(String(180), default="admin@verifai.com")
    high_amount_limit: Mapped[float] = mapped_column(Float, default=1000000)
    minimum_ocr_confidence: Mapped[int] = mapped_column(Integer, default=35)
    suspicious_keyword_sensitivity: Mapped[str] = mapped_column(String(20), default="medium")
    date_inconsistency_days: Mapped[int] = mapped_column(Integer, default=31)
    rule_missing_fields: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_suspicious_keywords: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_date_consistency: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_unusual_amount: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_duplicate_numbers: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_ocr_confidence: Mapped[bool] = mapped_column(Boolean, default=True)
    email_notifications: Mapped[bool] = mapped_column(Boolean, default=True)
    timezone: Mapped[str] = mapped_column(String(80), default="Asia/Kolkata")
    appearance: Mapped[str] = mapped_column(String(20), default="light")
    workspace_name: Mapped[str] = mapped_column(String(120), default="Admin workspace")

Base.metadata.create_all(engine)

def migrate_audit_columns():
    existing = {column["name"] for column in inspect(engine).get_columns("audit_logs")}
    additions = {"document_name": "VARCHAR(255)", "status": "VARCHAR(40)", "risk_level": "VARCHAR(20)"}
    with engine.begin() as connection:
        for name, column_type in additions.items():
            if name not in existing:
                connection.execute(sql_text(f"ALTER TABLE audit_logs ADD COLUMN {name} {column_type}"))
    settings_columns = {column["name"] for column in inspect(engine).get_columns("app_settings")}
    settings_additions = {"appearance": "VARCHAR(20)", "workspace_name": "VARCHAR(120)"}
    with engine.begin() as connection:
        for name, column_type in settings_additions.items():
            if name not in settings_columns:
                connection.execute(sql_text(f"ALTER TABLE app_settings ADD COLUMN {name} {column_type}"))

migrate_audit_columns()

class CompareRequest(BaseModel):
    invoice_id: int
    purchase_order_id: int

class DocumentComparisonRequest(BaseModel):
    left_document_id: int
    right_document_id: int

class SettingsPayload(BaseModel):
    profileName: str
    profileEmail: str
    highAmountLimit: float
    minimumOcrConfidence: int
    suspiciousKeywordSensitivity: str
    dateInconsistencyDays: int
    rules: dict[str, bool]
    emailNotifications: bool
    timezone: str
    appearance: str = "light"
    workspaceName: str = "Admin workspace"

app = FastAPI(title="VerifyAI API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/files", StaticFiles(directory=UPLOAD_DIR), name="files")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def log(db: Session, action: str, detail: str, severity: str = "INFO", document: Optional[Document] = None, status: Optional[str] = None, risk_level: Optional[str] = None):
    db.add(AuditLog(action=action, detail=detail, severity=severity.upper(), document_name=document.file_name if document else None, status=status or (document.status if document else None), risk_level=risk_level or (document.risk_level if document else None)))
    db.commit()

def settings_defaults() -> dict:
    return {"profileName": "Alex Morgan", "profileEmail": "admin@verifai.com", "highAmountLimit": 1000000, "minimumOcrConfidence": 35, "suspiciousKeywordSensitivity": "medium", "dateInconsistencyDays": 31, "rules": {"missingFields": True, "suspiciousKeywords": True, "dateConsistency": True, "unusualAmount": True, "duplicateNumbers": True, "ocrConfidence": True}, "emailNotifications": True, "timezone": "Asia/Kolkata", "appearance": "light", "workspaceName": "Admin workspace"}

def get_settings(db: Session) -> AppSettings:
    settings = db.get(AppSettings, 1)
    if not settings:
        settings = AppSettings(id=1)
        db.add(settings); db.commit(); db.refresh(settings)
    else:
        changed = False
        for field, value in (("appearance", "light"), ("workspace_name", "Admin workspace")):
            if getattr(settings, field) is None:
                setattr(settings, field, value); changed = True
        if changed:
            db.commit(); db.refresh(settings)
    return settings

def serialize_settings(settings: AppSettings) -> dict:
    return {"profileName": settings.profile_name, "profileEmail": settings.profile_email, "highAmountLimit": settings.high_amount_limit, "minimumOcrConfidence": settings.minimum_ocr_confidence, "suspiciousKeywordSensitivity": settings.suspicious_keyword_sensitivity, "dateInconsistencyDays": settings.date_inconsistency_days, "rules": {"missingFields": settings.rule_missing_fields, "suspiciousKeywords": settings.rule_suspicious_keywords, "dateConsistency": settings.rule_date_consistency, "unusualAmount": settings.rule_unusual_amount, "duplicateNumbers": settings.rule_duplicate_numbers, "ocrConfidence": settings.rule_ocr_confidence}, "emailNotifications": settings.email_notifications, "timezone": settings.timezone, "appearance": settings.appearance, "workspaceName": settings.workspace_name}

def serialize(document: Document):
    extracted = json.loads(document.extracted_data or "{}")
    return {"id": document.id, "fileName": document.file_name, "documentType": document.document_type, "vendor": document.vendor, "invoiceNumber": document.invoice_number, "poNumber": document.po_number, "invoiceDate": document.invoice_date, "amount": document.amount, "taxAmount": document.tax_amount, "score": document.score, "status": document.status, "riskLevel": document.risk_level, "confidence": document.confidence, "mismatchCount": document.mismatch_count, "createdAt": document.created_at.isoformat(), "extractedData": extracted, "extractedText": extracted.get("text", ""), "processingStatus": extracted.get("processingStatus", "PENDING")}

def extract_text(path: Path, content_type: str) -> tuple[str, str]:
    """Extract text from PDFs with PyMuPDF and raster images with Tesseract."""
    if content_type == "application/pdf":
        if fitz is None:
            raise HTTPException(503, "PDF extraction is unavailable. Install PyMuPDF.")
        try:
            with fitz.open(path) as pdf:
                return "\n".join(page.get_text("text") for page in pdf).strip(), "OCR_COMPLETE"
        except Exception as error:
            raise HTTPException(422, f"Could not read PDF: {error}") from error
    if Image is None or pytesseract is None:
        raise HTTPException(503, "Image OCR is unavailable. Install Pillow, pytesseract, and Tesseract OCR.")
    try:
        with Image.open(path) as image:
            return pytesseract.image_to_string(image).strip(), "OCR_COMPLETE"
    except Exception as error:
        raise HTTPException(422, f"Could not process image OCR: {error}") from error

def first_match(text: str, patterns: list[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip(" :#-\t")
    return ""

def parse_date(value: str) -> Optional[datetime]:
    for pattern in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d %b %Y", "%d %B %Y", "%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(value.strip(), pattern)
        except ValueError:
            continue
    return None

def parse_amount(value: str) -> float:
    cleaned = re.sub(r"[^0-9.]", "", value.replace(",", ""))
    try:
        return float(cleaned) if cleaned else 0
    except ValueError:
        return 0

def shift_month(month: datetime, offset: int) -> datetime:
    index = month.year * 12 + month.month - 1 + offset
    return datetime(index // 12, index % 12 + 1, 1)

def analyze_document(text: str, document_type: str, db: Session, document_id: Optional[int] = None) -> dict:
    """Parse common business fields and score deterministic verification rules."""
    settings = get_settings(db)
    rules = serialize_settings(settings)["rules"]
    invoice_number = first_match(text, [r"(?:invoice\s*(?:number|no|#)|inv\s*no)\s*[:#-]?\s*([A-Z0-9][A-Z0-9/_-]+)"])
    po_number = first_match(text, [r"(?:purchase\s*order|p\.?o\.?)\s*(?:number|no|#)?\s*[:#-]?\s*([A-Z0-9][A-Z0-9/_-]+)"])
    vendor = first_match(text, [r"(?:vendor|supplier|seller|billed\s*by)\s*[:#-]?\s*(.+)"])
    date_text = first_match(text, [r"(?:invoice\s*)?date\s*[:#-]?\s*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4}|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{1,2}\s+[A-Za-z]+\s+[0-9]{4})"])
    amount_text = first_match(text, [r"(?:grand\s*total|total\s*amount|amount\s*due|total)\s*[:#-]?\s*(?:INR|Rs\.?|₹|USD|\$)?\s*([0-9][0-9,.]*)"])
    tax_text = first_match(text, [r"(?:tax|gst|vat)\s*(?:amount)?\s*[:#-]?\s*(?:INR|Rs\.?|₹|USD|\$)?\s*([0-9][0-9,.]*)"])
    parsed_date = parse_date(date_text) if date_text else None
    fields = {"documentNumber": invoice_number if document_type == "Invoice" else po_number, "invoiceNumber": invoice_number, "poNumber": po_number, "vendor": vendor, "date": date_text, "totalAmount": parse_amount(amount_text), "taxAmount": parse_amount(tax_text)}
    anomalies: list[dict] = []
    required = ["documentNumber", "vendor", "date", "totalAmount"] if document_type in {"Invoice", "Purchase Order"} else ["vendor", "date"]
    if rules["missingFields"]:
        for field in required:
            if not fields[field]: anomalies.append({"code": "MISSING_FIELD", "field": field, "message": f"Missing {field.replace('documentNumber', 'document number').replace('totalAmount', 'total amount')}"})
    keyword_pattern = r"\b(?:fraud|fake|altered|urgent\s*cash|bitcoin|do\s*not\s*pay|confidential)\b"
    if settings.suspicious_keyword_sensitivity == "high": keyword_pattern = r"\b(?:fraud|fake|altered|urgent\s*cash|bitcoin|do\s*not\s*pay|confidential|cash|unverified|override|gift\s*card|wire\s*transfer)\b"
    if settings.suspicious_keyword_sensitivity == "low": keyword_pattern = r"\b(?:fraud|fake|altered|bitcoin)\b"
    if rules["suspiciousKeywords"]:
        suspicious_terms = re.findall(keyword_pattern, text, re.IGNORECASE)
        if suspicious_terms: anomalies.append({"code": "SUSPICIOUS_KEYWORD", "field": "text", "message": f"Suspicious keyword detected: {suspicious_terms[0]}"})
    if parsed_date is None and date_text: anomalies.append({"code": "INVALID_DATE", "field": "date", "message": "Date could not be parsed"})
    if parsed_date and parsed_date > datetime.utcnow() + timedelta(days=1): anomalies.append({"code": "FUTURE_DATE", "field": "date", "message": "Document date is in the future"})
    date_values = re.findall(r"\b(?:date|dated)\b\s*[:#-]?\s*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4})", text, re.IGNORECASE)
    parsed_dates = [parse_date(value) for value in date_values]
    if rules["dateConsistency"] and len([value for value in parsed_dates if value]) > 1 and (max(parsed_dates) - min(parsed_dates)).days > settings.date_inconsistency_days: anomalies.append({"code": "INCONSISTENT_DATES", "field": "date", "message": f"Document dates differ by more than {settings.date_inconsistency_days} days"})
    if rules["unusualAmount"] and fields["totalAmount"] > settings.high_amount_limit: anomalies.append({"code": "UNUSUAL_AMOUNT", "field": "totalAmount", "message": f"Amount exceeds configured limit of {settings.high_amount_limit:,.0f}"})
    duplicate_query = db.query(Document).filter(Document.invoice_number == invoice_number if document_type == "Invoice" else Document.po_number == po_number)
    if document_id: duplicate_query = duplicate_query.filter(Document.id != document_id)
    if rules["duplicateNumbers"] and (invoice_number if document_type == "Invoice" else po_number) and duplicate_query.first(): anomalies.append({"code": "DUPLICATE_NUMBER", "field": "documentNumber", "message": "Document number already exists in this workspace"})
    if rules["ocrConfidence"] and len(text.strip()) < settings.minimum_ocr_confidence: anomalies.append({"code": "LOW_OCR_CONFIDENCE", "field": "text", "message": f"OCR returned fewer than {settings.minimum_ocr_confidence} characters"})
    confidence = max(35, min(99, 98 - len(anomalies) * 12))
    score = max(0, confidence - len(anomalies) * 4)
    status = "VERIFIED" if not anomalies else "SUSPICIOUS" if any(item["code"] in {"DUPLICATE_NUMBER", "SUSPICIOUS_KEYWORD", "UNUSUAL_AMOUNT", "LOW_OCR_CONFIDENCE"} for item in anomalies) else "MISMATCH FOUND"
    risk = "LOW" if score >= 90 else "MEDIUM" if score >= 70 else "HIGH"
    fields.update({"text": text, "processingStatus": "OCR_COMPLETE", "fileType": "", "characterCount": len(text), "anomalies": anomalies})
    return {"fields": fields, "anomalies": anomalies, "confidence": confidence, "score": score, "status": status, "riskLevel": risk}

def persist_analysis(item: Document, analysis: dict, file_type: str) -> None:
    fields = analysis["fields"]
    item.vendor = fields["vendor"] or "Unknown vendor"
    item.invoice_number = fields["invoiceNumber"]
    item.po_number = fields["poNumber"]
    item.invoice_date = fields["date"]
    item.amount = fields["totalAmount"]
    item.tax_amount = fields["taxAmount"]
    item.score = analysis["score"]
    item.status = analysis["status"]
    item.risk_level = analysis["riskLevel"]
    item.confidence = analysis["confidence"]
    fields["fileType"] = file_type
    item.extracted_data = json.dumps(fields)

async def save_upload(file: UploadFile) -> tuple[Path, str, str]:
    original_name = file.filename or "document"
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS or file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(400, "Only PDF, JPG, JPEG, and PNG files are supported")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", Path(original_name).name)
    destination = UPLOAD_DIR / f"{uuid.uuid4().hex[:12]}_{safe_name}"
    total = 0
    try:
        with destination.open("wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "File is too large. Maximum size is 25 MB")
                buffer.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination, safe_name, file.content_type

def seed(db: Session):
    if db.query(Document).count(): return
    examples = [
        ("INV-2024-0842.pdf", "Invoice", "Apex Industrial Supplies", "INV-2024-0842", "PO-7781", "2024-10-24", 45800, 8244, 96, "VERIFIED", "LOW", 98, 0),
        ("INV-2024-0839.pdf", "Invoice", "Northstar Logistics", "INV-2024-0839", "PO-7764", "2024-10-21", 51200, 9216, 71, "MISMATCH FOUND", "MEDIUM", 88, 2),
        ("PO-7764.pdf", "Purchase Order", "Northstar Logistics", "", "PO-7764", "2024-10-18", 48000, 8640, 0, "PENDING REVIEW", "MEDIUM", 0, 0),
        ("contract-apex-q4.pdf", "Contract", "Apex Industrial Supplies", "", "", "2024-10-02", 0, 0, 84, "VERIFIED", "LOW", 91, 0),
        ("INV-2024-0831.png", "Invoice", "Brightline Office Co.", "INV-2024-0831", "PO-7741", "2024-10-16", 12600, 2268, 42, "SUSPICIOUS", "HIGH", 74, 3),
    ]
    for row in examples:
        name, kind, vendor, inv, po, date, amount, tax, score, status, risk, confidence, mismatches = row
        db.add(Document(file_name=name, document_type=kind, vendor=vendor, invoice_number=inv, po_number=po, invoice_date=date, amount=amount, tax_amount=tax, score=score, status=status, risk_level=risk, confidence=confidence, mismatch_count=mismatches, extracted_data='{"lineItems":[{"description":"Industrial components","quantity":12,"unitPrice":3800}],"currency":"INR"}', created_at=datetime.utcnow() - timedelta(days=len(examples))))
    db.commit()
    log(db, "System initialized", "Demo workspace seeded with verification records")

@app.on_event("startup")
def startup():
    with SessionLocal() as db: seed(db)

@app.get("/health")
def health(): return {"status": "ok", "service": "VerifyAI"}

@app.get("/settings")
def settings(db: Session = Depends(get_db)):
    return serialize_settings(get_settings(db))

@app.put("/settings")
def update_settings(payload: SettingsPayload, db: Session = Depends(get_db)):
    if not payload.profileName.strip() or "@" not in payload.profileEmail: raise HTTPException(422, "Enter a valid profile name and email")
    if payload.highAmountLimit <= 0 or not 0 <= payload.minimumOcrConfidence <= 100 or payload.dateInconsistencyDays < 1: raise HTTPException(422, "Threshold values are outside the allowed range")
    if payload.suspiciousKeywordSensitivity not in {"low", "medium", "high"}: raise HTTPException(422, "Invalid keyword sensitivity")
    settings = get_settings(db)
    settings.profile_name, settings.profile_email = payload.profileName.strip(), payload.profileEmail.strip()
    settings.high_amount_limit, settings.minimum_ocr_confidence = payload.highAmountLimit, payload.minimumOcrConfidence
    settings.suspicious_keyword_sensitivity, settings.date_inconsistency_days = payload.suspiciousKeywordSensitivity, payload.dateInconsistencyDays
    settings.rule_missing_fields, settings.rule_suspicious_keywords = payload.rules.get("missingFields", True), payload.rules.get("suspiciousKeywords", True)
    settings.rule_date_consistency, settings.rule_unusual_amount = payload.rules.get("dateConsistency", True), payload.rules.get("unusualAmount", True)
    settings.rule_duplicate_numbers, settings.rule_ocr_confidence = payload.rules.get("duplicateNumbers", True), payload.rules.get("ocrConfidence", True)
    settings.email_notifications, settings.timezone = payload.emailNotifications, payload.timezone
    settings.appearance, settings.workspace_name = payload.appearance, payload.workspaceName.strip() or "Admin workspace"
    db.commit(); log(db, "Settings Updated", "Verification rules and workspace preferences updated", "INFO")
    return serialize_settings(settings)

@app.post("/settings/reset")
def reset_settings(db: Session = Depends(get_db)):
    settings = get_settings(db)
    defaults = settings_defaults()
    settings.profile_name, settings.profile_email = defaults["profileName"], defaults["profileEmail"]
    settings.high_amount_limit, settings.minimum_ocr_confidence = defaults["highAmountLimit"], defaults["minimumOcrConfidence"]
    settings.suspicious_keyword_sensitivity, settings.date_inconsistency_days = defaults["suspiciousKeywordSensitivity"], defaults["dateInconsistencyDays"]
    rules = defaults["rules"]
    settings.rule_missing_fields, settings.rule_suspicious_keywords = rules["missingFields"], rules["suspiciousKeywords"]
    settings.rule_date_consistency, settings.rule_unusual_amount = rules["dateConsistency"], rules["unusualAmount"]
    settings.rule_duplicate_numbers, settings.rule_ocr_confidence = rules["duplicateNumbers"], rules["ocrConfidence"]
    settings.email_notifications, settings.timezone = defaults["emailNotifications"], defaults["timezone"]
    settings.appearance, settings.workspace_name = defaults["appearance"], defaults["workspaceName"]
    db.commit(); log(db, "Settings Reset", "Verification settings restored to defaults", "WARNING")
    return serialize_settings(settings)

@app.get("/documents")
def documents(db: Session = Depends(get_db)):
    return [serialize(item) for item in db.query(Document).order_by(desc(Document.created_at)).all()]

@app.get("/verification-history")
def verification_history(search: str = "", document_type: str = "", status: str = "", risk_level: str = "", sort: str = "newest", page: int = Query(1, ge=1), page_size: int = Query(8, ge=1, le=50), db: Session = Depends(get_db)):
    query = db.query(Document)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter((Document.file_name.ilike(term)) | (Document.invoice_number.ilike(term)) | (Document.po_number.ilike(term)) | (Document.vendor.ilike(term)))
    if document_type: query = query.filter(Document.document_type == document_type)
    if status: query = query.filter(Document.status == status)
    if risk_level: query = query.filter(Document.risk_level == risk_level)
    query = query.order_by(Document.created_at.asc() if sort == "oldest" else desc(Document.created_at))
    total = query.count()
    records = query.offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [serialize(item) for item in records], "total": total, "page": page, "pageSize": page_size, "pages": max(1, (total + page_size - 1) // page_size)}

@app.get("/documents/{document_id}")
def document(document_id: int, db: Session = Depends(get_db)):
    item = db.get(Document, document_id)
    if not item: raise HTTPException(404, "Document not found")
    return serialize(item)

@app.post("/upload")
async def upload(file: UploadFile = File(...), document_type: str = "Invoice", db: Session = Depends(get_db)):
    destination, safe_name, content_type = await save_upload(file)
    text, processing_status = extract_text(destination, content_type)
    analysis = analyze_document(text, document_type, db)
    analysis["fields"]["processingStatus"] = processing_status
    item = Document(file_name=safe_name, document_type=document_type, vendor="Awaiting extraction", status="PENDING REVIEW", risk_level="MEDIUM", extracted_data="{}")
    db.add(item); db.flush()
    persist_analysis(item, analysis, content_type)
    db.commit(); db.refresh(item)
    log(db, "Document Uploaded", f"{safe_name} uploaded for {document_type}", "INFO", item)
    log(db, "OCR Extraction Completed", f"Extracted {len(text)} characters from {safe_name}", "INFO", item)
    if analysis["anomalies"]: log(db, "Anomalies Detected", f"{len(analysis['anomalies'])} anomaly rules triggered", "WARNING", item)
    log(db, "Verification Completed", f"Verification result: {item.status}", "WARNING" if analysis["anomalies"] else "INFO", item)
    return serialize(item)

@app.post("/extract")
def extract(document_id: int, db: Session = Depends(get_db)):
    item = db.get(Document, document_id)
    if not item: raise HTTPException(404, "Document not found")
    stored_file = next(UPLOAD_DIR.glob(f"*_{item.file_name}"), None)
    if stored_file is None:
        raise HTTPException(404, "Stored upload not found")
    content_type = "application/pdf" if stored_file.suffix.lower() == ".pdf" else "image/png" if stored_file.suffix.lower() == ".png" else "image/jpeg"
    text, processing_status = extract_text(stored_file, content_type)
    analysis = analyze_document(text, item.document_type, db, item.id)
    analysis["fields"]["processingStatus"] = processing_status
    persist_analysis(item, analysis, content_type)
    db.commit(); log(db, "Verification Started", f"OCR analysis started for {item.file_name}", "INFO", item); log(db, "OCR Extraction Completed", f"Extracted {len(text)} characters", "INFO", item)
    if analysis["anomalies"]: log(db, "Anomalies Detected", f"{len(analysis['anomalies'])} anomaly rules triggered", "WARNING", item)
    log(db, "Verification Completed", f"Verification result: {item.status}", "WARNING" if analysis["anomalies"] else "INFO", item)
    return serialize(item)

@app.post("/compare")
def compare(payload: CompareRequest, db: Session = Depends(get_db)):
    invoice, po = db.get(Document, payload.invoice_id), db.get(Document, payload.purchase_order_id)
    if not invoice or not po: raise HTTPException(404, "Both documents are required")
    checks = []
    def check(field, label, invoice_value, po_value, kind="match"):
        matched = invoice_value == po_value
        checks.append({"field": field, "label": label, "invoiceValue": invoice_value, "poValue": po_value, "status": "matched" if matched else kind, "difference": abs(float(invoice_value or 0) - float(po_value or 0)) if isinstance(invoice_value, (int, float)) and isinstance(po_value, (int, float)) else None})
    check("vendor", "Vendor name", invoice.vendor, po.vendor, "warning")
    check("poNumber", "PO number", invoice.po_number, po.po_number, "mismatch")
    check("amount", "Total amount", invoice.amount, po.amount, "mismatch")
    check("invoiceDate", "Document date", invoice.invoice_date, po.invoice_date, "warning")
    mismatches = sum(1 for c in checks if c["status"] != "matched")
    score = max(0, 100 - mismatches * 14)
    invoice.score, invoice.mismatch_count, invoice.status = score, mismatches, "VERIFIED" if mismatches == 0 else "MISMATCH FOUND"
    invoice.risk_level = "LOW" if score >= 90 else "MEDIUM" if score >= 70 else "HIGH"
    invoice.confidence = min(99, 84 + score // 10)
    db.commit(); log(db, "Mismatch Detected" if mismatches else "Document Approved", f"{invoice.file_name} compared with {po.file_name}", "WARNING" if mismatches else "INFO", invoice)
    return {"invoice": serialize(invoice), "purchaseOrder": serialize(po), "checks": checks, "mismatches": mismatches, "score": score, "riskLevel": invoice.risk_level}

def comparison_field(label: str, left: object, right: object, numeric: bool = False) -> dict:
    left_text, right_text = str(left or "").strip(), str(right or "").strip()
    if not left_text or not right_text:
        status = "missing"
    elif numeric:
        status = "matched" if abs(float(left or 0) - float(right or 0)) < 0.01 else "mismatch"
    else:
        status = "matched" if left_text.casefold() == right_text.casefold() else "mismatch"
    difference = abs(float(left or 0) - float(right or 0)) if numeric and left_text and right_text else None
    return {"field": label, "leftValue": left, "rightValue": right, "status": status, "difference": difference}

def run_document_comparison(left: Document, right: Document) -> dict:
    left_extracted, right_extracted = json.loads(left.extracted_data or "{}"), json.loads(right.extracted_data or "{}")
    fields = [comparison_field("Document number", left.invoice_number or left.po_number, right.invoice_number or right.po_number), comparison_field("Date", left.invoice_date, right.invoice_date), comparison_field("Vendor", left.vendor, right.vendor), comparison_field("Total amount", left.amount, right.amount, True), comparison_field("Document type", left.document_type, right.document_type)]
    left_text, right_text = left_extracted.get("text", ""), right_extracted.get("text", "")
    text_similarity = round(SequenceMatcher(None, left_text.casefold(), right_text.casefold()).ratio() * 100)
    findings = []
    for field in fields:
        if field["status"] == "missing": findings.append({"code": "MISSING_INFORMATION", "message": f"Missing {field['field'].lower()} in one document"})
        elif field["status"] == "mismatch": findings.append({"code": "FIELD_MISMATCH", "message": f"{field['field']} values differ"})
    if left.invoice_number and left.invoice_number == right.invoice_number and abs(left.amount - right.amount) >= 0.01:
        findings.append({"code": "DUPLICATE_NUMBER_DIFFERENT_AMOUNT", "message": "Same document number has different total amounts"})
    if left.vendor and right.vendor and SequenceMatcher(None, left.vendor.casefold(), right.vendor.casefold()).ratio() < 0.7:
        findings.append({"code": "INCONSISTENT_VENDOR", "message": "Vendor details are materially different"})
    left_date, right_date = parse_date(left.invoice_date), parse_date(right.invoice_date)
    if left_date and right_date and abs((left_date - right_date).days) > 31:
        findings.append({"code": "UNUSUAL_DATE_DIFFERENCE", "message": "Document dates differ by more than 31 days"})
    if text_similarity < 35: findings.append({"code": "OCR_TEXT_DIFFERENCE", "message": "OCR text has low similarity"})
    matched = sum(field["status"] == "matched" for field in fields)
    score = max(0, round((matched / len(fields)) * 80 + text_similarity * 0.2 - len(findings) * 5))
    result = "MATCHED" if not findings else "SUSPICIOUS" if any(item["code"] in {"DUPLICATE_NUMBER_DIFFERENT_AMOUNT", "INCONSISTENT_VENDOR", "OCR_TEXT_DIFFERENCE"} for item in findings) else "DIFFERENCES FOUND"
    return {"left": serialize(left), "right": serialize(right), "fields": fields, "ocrTextSimilarity": text_similarity, "findings": findings, "similarityScore": score, "result": result}

@app.post("/comparisons")
def create_comparison(payload: DocumentComparisonRequest, db: Session = Depends(get_db)):
    if payload.left_document_id == payload.right_document_id: raise HTTPException(400, "Choose two different documents")
    left, right = db.get(Document, payload.left_document_id), db.get(Document, payload.right_document_id)
    if not left or not right: raise HTTPException(404, "Both documents are required")
    result = run_document_comparison(left, right)
    record = Comparison(left_document_id=left.id, right_document_id=right.id, similarity_score=result["similarityScore"], result=result["result"], findings=json.dumps(result["findings"]))
    db.add(record); db.commit(); db.refresh(record)
    result["comparisonId"], result["createdAt"] = record.id, record.created_at.isoformat()
    log(db, "Documents Compared", f"{left.file_name} compared with {right.file_name}", "WARNING" if result["findings"] else "INFO", left)
    return result

@app.get("/comparisons")
def comparisons(db: Session = Depends(get_db)):
    records = db.query(Comparison).order_by(desc(Comparison.created_at)).limit(10).all()
    return [{"id": record.id, "leftDocumentId": record.left_document_id, "rightDocumentId": record.right_document_id, "similarityScore": record.similarity_score, "result": record.result, "findings": json.loads(record.findings or "[]"), "createdAt": record.created_at.isoformat(), "leftFileName": db.get(Document, record.left_document_id).file_name if db.get(Document, record.left_document_id) else "Deleted document", "rightFileName": db.get(Document, record.right_document_id).file_name if db.get(Document, record.right_document_id) else "Deleted document"} for record in records]

@app.post("/verify")
def verify(document_id: int, db: Session = Depends(get_db)):
    item = db.get(Document, document_id)
    if not item: raise HTTPException(404, "Document not found")
    stored_file = next(UPLOAD_DIR.glob(f"*_{item.file_name}"), None)
    if stored_file is None:
        log(db, "Verification Failed", f"Stored upload not found for document {document_id}", "CRITICAL", item, "FAILED", "HIGH")
        raise HTTPException(404, "Stored upload not found")
    content_type = "application/pdf" if stored_file.suffix.lower() == ".pdf" else "image/png" if stored_file.suffix.lower() == ".png" else "image/jpeg"
    text, processing_status = extract_text(stored_file, content_type)
    analysis = analyze_document(text, item.document_type, db, item.id)
    analysis["fields"]["processingStatus"] = processing_status
    persist_analysis(item, analysis, content_type)
    db.commit(); log(db, "Verification Started", f"Dynamic risk analysis run for {item.file_name}", "INFO", item)
    if analysis["anomalies"]: log(db, "Anomalies Detected", f"{len(analysis['anomalies'])} anomaly rules triggered", "WARNING", item)
    log(db, "Verification Completed", f"Verification result: {item.status}", "WARNING" if analysis["anomalies"] else "INFO", item)
    return serialize(item)

@app.delete("/documents/{document_id}")
def delete_document(document_id: int, db: Session = Depends(get_db)):
    item = db.get(Document, document_id)

    if not item:
        raise HTTPException(404, "Document not found")

    file_name = item.file_name
    risk_level = item.risk_level

    db.delete(item)
    db.commit()

    db.add(AuditLog(
        action="Record Deletion",
        detail=f"{file_name} removed from verification history",
        severity="WARNING",
        document_name=file_name,
        status="DELETED",
        risk_level=risk_level
    ))
    db.commit()

    return {"deleted": True}

@app.get("/analytics")
def analytics(db: Session = Depends(get_db)):
    items = db.query(Document).all()
    counts = {"VERIFIED": sum(i.status == "VERIFIED" for i in items), "SUSPICIOUS": sum(i.status == "SUSPICIOUS" for i in items), "PENDING REVIEW": sum(i.status == "PENDING REVIEW" for i in items), "MISMATCH FOUND": sum(i.status == "MISMATCH FOUND" for i in items)}
    risk_counts = {level: sum(i.risk_level == level for i in items) for level in ("LOW", "MEDIUM", "HIGH")}
    average_risk_score = round(sum(i.score for i in items) / len(items), 1) if items else 0
    type_counts: dict[str, int] = {}
    for item in items:
        type_counts[item.document_type] = type_counts.get(item.document_type, 0) + 1
    anomaly_counts: dict[str, int] = {}
    for item in items:
        for anomaly in json.loads(item.extracted_data or "{}").get("anomalies", []):
            category = anomaly.get("code", "OTHER").replace("_", " ").title()
            anomaly_counts[category] = anomaly_counts.get(category, 0) + 1
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    trends = []
    for offset in range(5, -1, -1):
        month_start = shift_month(today.replace(day=1), -offset)
        next_month = shift_month(month_start, 1)
        month_items = [item for item in items if month_start <= item.created_at < next_month]
        trends.append({"month": month_start.strftime("%b"), "uploads": len(month_items), "verified": sum(item.status == "VERIFIED" for item in month_items), "suspicious": sum(item.status == "SUSPICIOUS" for item in month_items), "pending": sum(item.status == "PENDING REVIEW" for item in month_items)})
    recent = [{"id": item.id, "fileName": item.file_name, "documentType": item.document_type, "status": item.status, "riskLevel": item.risk_level, "score": item.score, "createdAt": item.created_at.isoformat()} for item in sorted(items, key=lambda value: value.created_at, reverse=True)[:8]]
    status = [{"name": "Verified", "value": counts["VERIFIED"]}, {"name": "Mismatch", "value": counts["MISMATCH FOUND"]}, {"name": "Pending", "value": counts["PENDING REVIEW"]}, {"name": "Suspicious", "value": counts["SUSPICIOUS"]}]
    risk_distribution = [{"name": level.title(), "value": risk_counts[level]} for level in ("LOW", "MEDIUM", "HIGH")]
    anomaly_categories = [{"name": name, "value": value} for name, value in sorted(anomaly_counts.items(), key=lambda pair: pair[1], reverse=True)]
    document_types = [{"name": name, "value": value} for name, value in sorted(type_counts.items(), key=lambda pair: pair[1], reverse=True)]
    return {"total": len(items), "verified": counts["VERIFIED"], "mismatch": counts["MISMATCH FOUND"], "pending": counts["PENDING REVIEW"], "suspicious": counts["SUSPICIOUS"], "totalDocuments": len(items), "verifiedDocuments": counts["VERIFIED"], "suspiciousDocuments": counts["SUSPICIOUS"], "pendingReviews": counts["PENDING REVIEW"], "averageRiskScore": average_risk_score, "status": status, "riskDistribution": risk_distribution, "documentTypeDistribution": document_types, "verificationTrends": trends, "anomalyCategories": anomaly_categories, "recentActivity": recent, "monthly": trends}

@app.get("/audit-logs")
def audit_logs(search: str = "", action_type: str = "", date_from: str = "", date_to: str = "", db: Session = Depends(get_db)):
    query = db.query(AuditLog)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter((AuditLog.action.ilike(term)) | (AuditLog.detail.ilike(term)) | (AuditLog.document_name.ilike(term)))
    if action_type: query = query.filter(AuditLog.action == action_type)
    if date_from:
        try: query = query.filter(AuditLog.created_at >= datetime.fromisoformat(date_from))
        except ValueError: raise HTTPException(400, "date_from must be an ISO date")
    if date_to:
        try: query = query.filter(AuditLog.created_at < datetime.fromisoformat(date_to) + timedelta(days=1))
        except ValueError: raise HTTPException(400, "date_to must be an ISO date")
    return [{"id": x.id, "action": x.action, "detail": x.detail, "severity": x.severity.upper(), "documentName": x.document_name, "status": x.status, "riskLevel": x.risk_level, "createdAt": x.created_at.isoformat()} for x in query.order_by(desc(AuditLog.created_at)).limit(100).all()]
