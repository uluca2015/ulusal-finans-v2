from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Ulusal Finans V2 API çalışıyor 🚀"}

@app.get("/health")
def health():
    return {"status": "ok"}
