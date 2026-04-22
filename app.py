import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Numeric, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# =========================
# Ayarlar
# =========================
DATABASE_URL = os.getenv("DATABASE_URL", "")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL ortam değişkeni tanımlı değil")

# =========================
# DB
# =========================
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# Güvenlik
# =========================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Yetkisiz erişim")

    token = authorization.replace("Bearer ", "").strip()

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Geçersiz token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Geçersiz token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")
    return user


# =========================
# Modeller
# =========================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="admin", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Income(Base):
    __tablename__ = "incomes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=True)
    amount = Column(Numeric(14, 2), nullable=False)
    income_date = Column(String(20), nullable=True)
    note = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Expense(Base):
    __tablename__ = "expenses"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=True)
    amount = Column(Numeric(14, 2), nullable=False)
    expense_date = Column(String(20), nullable=True)
    note = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# =========================
# Şemalar
# =========================
class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None
    role: str = "admin"


class IncomeCreate(BaseModel):
    title: str
    category: Optional[str] = None
    amount: float
    income_date: Optional[str] = None
    note: Optional[str] = None


class ExpenseCreate(BaseModel):
    title: str
    category: Optional[str] = None
    amount: float
    expense_date: Optional[str] = None
    note: Optional[str] = None


# =========================
# Uygulama
# =========================
app = FastAPI(title="Ulusal Finans V2 API")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

    if ADMIN_PASSWORD:
        db = SessionLocal()
        try:
            existing = db.query(User).filter(User.username == ADMIN_USERNAME).first()
            if not existing:
                admin = User(
                    username=ADMIN_USERNAME,
                    password_hash=hash_password(ADMIN_PASSWORD),
                    full_name="Sistem Yöneticisi",
                    role="admin",
                )
                db.add(admin)
                db.commit()
        finally:
            db.close()


# =========================
# Genel endpointler
# =========================
@app.get("/")
def root():
    return {"message": "Ulusal Finans V2 API çalışıyor 🚀"}


@app.head("/")
def root_head():
    return {}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/db-check")
def db_check():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"database": "connected"}


# =========================
# Auth
# =========================
@app.post("/api/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı")

    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


# =========================
# Kullanıcı
# =========================
@app.post("/api/users")
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Sadece admin kullanıcı ekleyebilir")

    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Bu kullanıcı zaten var")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role,
    }


# =========================
# Gelir
# =========================
@app.post("/api/incomes")
def create_income(
    payload: IncomeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = Income(
        title=payload.title,
        category=payload.category,
        amount=payload.amount,
        income_date=payload.income_date,
        note=payload.note,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "message": "Gelir kaydı oluşturuldu"}


@app.get("/api/incomes")
def list_incomes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.query(Income).order_by(Income.id.desc()).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category,
            "amount": float(r.amount),
            "income_date": r.income_date,
            "note": r.note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# =========================
# Gider
# =========================
@app.post("/api/expenses")
def create_expense(
    payload: ExpenseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = Expense(
        title=payload.title,
        category=payload.category,
        amount=payload.amount,
        expense_date=payload.expense_date,
        note=payload.note,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "message": "Gider kaydı oluşturuldu"}


@app.get("/api/expenses")
def list_expenses(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = db.query(Expense).order_by(Expense.id.desc()).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category,
            "amount": float(r.amount),
            "expense_date": r.expense_date,
            "note": r.note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
