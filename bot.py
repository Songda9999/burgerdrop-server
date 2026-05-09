"""
BurgerDrop — Bot + PayWay Server
----------------------------------
Handles:
  1. Telegram bot /start → shows Mini App button
  2. POST /api/create-transaction → creates PayWay transaction, returns hash + metadata
  3. POST /api/payway-callback   → receives PayWay payment pushback, verifies signature,
                                   notifies restaurant group, confirms to customer
  4. GET  /api/check-transaction → polls PayWay for payment status (optional)

Requirements:
  pip install python-telegram-bot==20.7 fastapi uvicorn httpx python-dotenv

Run:
  uvicorn bot:app --host 0.0.0.0 --port 8000

Then expose publicly with:
  ngrok http 8000          (for local dev)
  railway up               (for production)
"""

import hashlib
import hmac
import base64
import json
import time
import os
import logging
import httpx
from datetime import datetime
from dotenv import load_dotenv

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

from telegram import Update, WebAppInfo, KeyboardButton, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════
#  CONFIG  ← put these in a .env file
# ══════════════════════════════════════════
BOT_TOKEN           = os.getenv("BOT_TOKEN", "YOUR_BOT_TOKEN")
MERCHANT_ID         = os.getenv("MERCHANT_ID", "ec000002")          # from PayWay sandbox email
API_KEY             = os.getenv("API_KEY", "YOUR_PAYWAY_API_KEY")   # from PayWay sandbox email
MINI_APP_URL        = os.getenv("MINI_APP_URL", "https://your-site.vercel.app")
RESTAURANT_CHAT_ID  = int(os.getenv("RESTAURANT_CHAT_ID", "-1001234567890"))
SERVER_URL          = os.getenv("SERVER_URL", "https://your-server.railway.app")  # public URL of THIS server

# PayWay endpoints
PAYWAY_SANDBOX = "https://checkout-sandbox.payway.com.kh/api/payment-gateway/v1/payments"
PAYWAY_LIVE    = "https://checkout.payway.com.kh/api/payment-gateway/v1/payments"
PAYWAY_API     = PAYWAY_SANDBOX  # switch to PAYWAY_LIVE when going live
# ══════════════════════════════════════════

app = FastAPI(title="BurgerDrop Server")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory order store (use a real DB like Supabase/PostgreSQL in production)
pending_orders = {}  # tran_id → order details

# ── Telegram bot setup ───────────────────────────────────────────────────────
tg_app = Application.builder().token(BOT_TOKEN).build()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = ReplyKeyboardMarkup(
        [[KeyboardButton(text="🍔 Open Menu", web_app=WebAppInfo(url=MINI_APP_URL))]],
        resize_keyboard=True
    )
    await update.message.reply_text(
        "Welcome to *BurgerDrop* 🍔\n\nFresh smash burgers, delivered fast!\nTap below to browse our menu.",
        parse_mode="Markdown",
        reply_markup=keyboard
    )

tg_app.add_handler(CommandHandler("start", start))

@app.on_event("startup")
async def startup():
    await tg_app.initialize()
    await tg_app.start()
    # Register webhook so Telegram sends updates to this server
    webhook_url = f"{SERVER_URL}/telegram-webhook"
    await tg_app.bot.set_webhook(webhook_url)
    logger.info(f"Webhook set: {webhook_url}")

@app.on_event("shutdown")
async def shutdown():
    await tg_app.stop()

@app.post("/telegram-webhook")
async def telegram_webhook(request: Request):
    data = await request.json()
    update = Update.de_json(data, tg_app.bot)
    await tg_app.process_update(update)
    return {"ok": True}

# ── PayWay helpers ───────────────────────────────────────────────────────────

def generate_tran_id() -> str:
    """Unique transaction ID — timestamp + random suffix."""
    return str(int(time.time() * 1000))[-13:]

def generate_req_time() -> str:
    """PayWay req_time format: YYYYMMDDHHmmss"""
    return datetime.utcnow().strftime("%Y%m%d%H%M%S")

def generate_hash(params: dict, api_key: str) -> str:
    """
    PayWay HMAC-SHA512 hash.
    Sort fields alphabetically, concatenate values, sign with API key.
    """
    sorted_keys = sorted(params.keys())
    b4hash = "".join(str(params[k]) for k in sorted_keys if params[k] != "")
    signature = base64.b64encode(
        hmac.new(api_key.encode(), b4hash.encode(), hashlib.sha512).digest()
    ).decode()
    return signature

def verify_callback_signature(payload: dict, received_sig: str, api_key: str) -> bool:
    """Verify PayWay callback signature from X-PayWay-HMAC-SHA512 header."""
    sorted_payload = dict(sorted(payload.items()))
    b4hash = "".join(
        json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        for v in sorted_payload.values()
    )
    expected = base64.b64encode(
        hmac.new(api_key.encode(), b4hash.encode(), hashlib.sha512).digest()
    ).decode()
    return hmac.compare_digest(expected, received_sig)

# ── API: Create Transaction ───────────────────────────────────────────────────

class OrderItem(BaseModel):
    id: int
    name: str
    qty: int
    price: float

class CreateTransactionRequest(BaseModel):
    amount: str
    payment_option: str
    items: List[OrderItem]
    note: Optional[str] = ""
    tg_user_id: Optional[str] = ""
    firstname: Optional[str] = "Guest"
    lastname: Optional[str] = ""

@app.post("/api/create-transaction")
async def create_transaction(body: CreateTransactionRequest):
    tran_id  = generate_tran_id()
    req_time = generate_req_time()

    # Fields to hash — must match exactly what the form will POST
    hash_params = {
        "amount":        body.amount,
        "currency":      "USD",
        "firstname":     body.firstname,
        "lastname":      body.lastname,
        "merchant_id":   MERCHANT_ID,
        "payment_option": body.payment_option,
        "req_time":      req_time,
        "return_url":    f"{SERVER_URL}/api/payway-callback",
        "tran_id":       tran_id,
    }

    signed_hash = generate_hash(hash_params, API_KEY)

    # Save order to memory (replace with DB in production)
    pending_orders[tran_id] = {
        "tran_id":    tran_id,
        "tg_user_id": body.tg_user_id,
        "firstname":  body.firstname,
        "amount":     body.amount,
        "items":      [i.dict() for i in body.items],
        "note":       body.note,
        "status":     "pending",
    }

    logger.info(f"Created transaction {tran_id} for ${body.amount}")

    return {
        "tran_id":     tran_id,
        "merchant_id": MERCHANT_ID,
        "req_time":    req_time,
        "hash":        signed_hash,
        "return_url":  f"{SERVER_URL}/api/payway-callback",
    }

# ── API: PayWay Callback ──────────────────────────────────────────────────────

@app.post("/api/payway-callback")
async def payway_callback(request: Request):
    payload = await request.json()
    received_sig = request.headers.get("X-PayWay-HMAC-SHA512", "")

    # 1. Verify signature
    if not verify_callback_signature(payload, received_sig, API_KEY):
        logger.warning(f"Invalid PayWay signature for tran_id={payload.get('tran_id')}")
        raise HTTPException(status_code=401, detail="Invalid signature")

    tran_id = payload.get("tran_id", "")
    status  = payload.get("status", "")   # "0" = success
    apv     = payload.get("apv", "")

    logger.info(f"PayWay callback: tran_id={tran_id} status={status}")

    order = pending_orders.get(tran_id)
    if not order:
        logger.warning(f"Unknown tran_id: {tran_id}")
        return {"ok": True}  # still return 200 to PayWay

    if status == "0":  # Success
        order["status"] = "paid"
        order["apv"]    = apv
        await notify_restaurant(order)
        await confirm_customer(order)
    else:
        order["status"] = "failed"
        logger.info(f"Payment failed/cancelled: {tran_id}")

    return {"ok": True}

async def notify_restaurant(order: dict):
    """Send a clear order ticket to the restaurant Telegram group."""
    items_text = "\n".join(
        f"  • {i['name']} × {i['qty']}  —  ${float(i['price']) * i['qty']:.2f}"
        for i in order["items"]
    )
    note = order.get("note") or "—"
    msg = (
        f"🔔 *NEW ORDER — #{order['tran_id'][-6:]}*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"👤 {order['firstname']}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"{items_text}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📝 Note: {note}\n"
        f"💰 Total: *${order['amount']}*\n"
        f"✅ PAID via ABA PayWay\n"
        f"🧾 APV: `{order.get('apv', 'N/A')}`"
    )
    await tg_app.bot.send_message(
        chat_id=RESTAURANT_CHAT_ID,
        text=msg,
        parse_mode="Markdown"
    )
    logger.info(f"Order {order['tran_id']} sent to restaurant group")

async def confirm_customer(order: dict):
    """Send a payment confirmation to the customer."""
    if not order.get("tg_user_id"):
        return
    try:
        await tg_app.bot.send_message(
            chat_id=int(order["tg_user_id"]),
            text=(
                f"✅ *Payment confirmed!*\n\n"
                f"Thank you, {order['firstname']}! 🍔\n"
                f"Your order is being prepared.\n\n"
                f"Order: `#{order['tran_id'][-6:]}`\n"
                f"Total: *${order['amount']}*"
            ),
            parse_mode="Markdown"
        )
    except Exception as e:
        logger.warning(f"Could not message customer: {e}")

# ── API: Check Transaction Status (optional polling) ──────────────────────────

@app.get("/api/check-transaction/{tran_id}")
async def check_transaction(tran_id: str):
    """
    Poll PayWay for payment status.
    Respect PayWay's 600 req/s rate limit and stop once status is final.
    """
    req_time = generate_req_time()
    hash_params = {
        "merchant_id": MERCHANT_ID,
        "tran_id":     tran_id,
        "req_time":    req_time,
    }
    signed_hash = generate_hash(hash_params, API_KEY)

    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{PAYWAY_API}/check-transaction",
            data={
                "merchant_id": MERCHANT_ID,
                "tran_id":     tran_id,
                "req_time":    req_time,
                "hash":        signed_hash,
            }
        )
    return res.json()

# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "BurgerDrop server running 🍔"}
