from fastapi import FastAPI
from .db import engine
from .models import Base

app = FastAPI()

Base.metadata.create_all(bind=engine)

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
    return {"database": "connected"}
