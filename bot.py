import hashlib
import hmac
import base64
import json
import time
import os
import logging
from datetime import datetime
from contextlib import asynccontextmanager
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

BOT_TOKEN          = os.getenv("BOT_TOKEN", "")
MERCHANT_ID        = os.getenv("MERCHANT_ID", "")
API_KEY            = os.getenv("API_KEY", "")
MINI_APP_URL       = os.getenv("MINI_APP_URL", "")
RESTAURANT_CHAT_ID = int(os.getenv("RESTAURANT_CHAT_ID", "0"))
SERVER_URL         = os.getenv("SERVER_URL", "")

PAYWAY_API = "https://checkout-sandbox.payway.com.kh/api/payment-gateway/v1/payments"

pending_orders = {}
tg_app: Application = None


# ── Telegram handlers ─────────────────────────────────────────────────────────

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


# ── FastAPI lifespan (replaces @app.on_event for v21 compatibility) ───────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global tg_app

    # Build and start telegram app
    tg_app = Application.builder().token(BOT_TOKEN).build()
    tg_app.add_handler(CommandHandler("start", start))

    await tg_app.initialize()
    await tg_app.start()

    webhook_url = f"{SERVER_URL}/telegram-webhook"
    await tg_app.bot.set_webhook(webhook_url)
    logger.info(f"✅ Bot started. Webhook: {webhook_url}")

    yield  # app is running

    # Shutdown
    await tg_app.stop()
    await tg_app.shutdown()
    logger.info("Bot stopped.")


app = FastAPI(title="BurgerDrop Server", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/telegram-webhook")
async def telegram_webhook(request: Request):
    data = await request.json()
    update = Update.de_json(data, tg_app.bot)
    await tg_app.process_update(update)
    return {"ok": True}


# ── PayWay helpers ────────────────────────────────────────────────────────────

def generate_tran_id() -> str:
    return str(int(time.time() * 1000))[-13:]


def generate_req_time() -> str:
    return datetime.utcnow().strftime("%Y%m%d%H%M%S")


def generate_hash(params: dict, api_key: str) -> str:
    sorted_keys = sorted(params.keys())
    b4hash = "".join(str(params[k]) for k in sorted_keys if params[k] != "")
    signature = base64.b64encode(
        hmac.new(api_key.encode(), b4hash.encode(), hashlib.sha512).digest()
    ).decode()
    return signature


def verify_callback_signature(payload: dict, received_sig: str, api_key: str) -> bool:
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
    tran_id    = generate_tran_id()
    req_time   = generate_req_time()
    return_url = f"{SERVER_URL}/api/payway-callback"

    hash_params = {
        "amount":          body.amount,
        "currency":        "USD",
        "firstname":       body.firstname,
        "lastname":        body.lastname,
        "merchant_id":     MERCHANT_ID,
        "payment_option":  body.payment_option,
        "req_time":        req_time,
        "return_url":      return_url,
        "tran_id":         tran_id,
    }

    signed_hash = generate_hash(hash_params, API_KEY)

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
        "return_url":  return_url,
    }


# ── API: PayWay Callback ──────────────────────────────────────────────────────

@app.post("/api/payway-callback")
async def payway_callback(request: Request):
    payload      = await request.json()
    received_sig = request.headers.get("X-PayWay-HMAC-SHA512", "")

    if received_sig and not verify_callback_signature(payload, received_sig, API_KEY):
        logger.warning(f"Invalid PayWay signature for tran_id={payload.get('tran_id')}")
        raise HTTPException(status_code=401, detail="Invalid signature")

    tran_id = payload.get("tran_id", "")
    status  = payload.get("status", "")
    apv     = payload.get("apv", "")

    logger.info(f"PayWay callback: tran_id={tran_id} status={status}")

    order = pending_orders.get(tran_id)
    if not order:
        logger.warning(f"Unknown tran_id: {tran_id}")
        return {"ok": True}

    if status == "0":
        order["status"] = "paid"
        order["apv"]    = apv
        await notify_restaurant(order)
        await confirm_customer(order)
    else:
        order["status"] = "failed"

    return {"ok": True}


async def notify_restaurant(order: dict):
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


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "BurgerDrop server running 🍔"}
