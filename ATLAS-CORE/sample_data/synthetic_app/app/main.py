# SYNTHETIC sample application (not real software)
import os
from fastapi import FastAPI, Depends
import jwt, boto3, stripe

app = FastAPI()
app.add_middleware(CORSMiddleware)
DB_URL = os.environ["DATABASE_URL"]


@app.get("/health")
def health(): ...


@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user)): ...


@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: int): ...


@app.post("/checkout")
def checkout(user=Depends(get_current_user)): ...


@app.delete("/users/{user_id}")
def delete_user(user_id: int): ...
