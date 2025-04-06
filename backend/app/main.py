from . import models, database
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def server():
    return 'server run!'

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
