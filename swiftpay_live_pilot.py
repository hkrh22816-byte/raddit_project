"""SwiftPayIQ LIVE pilot, not enabled for public customers."""
import os
import hmac
import hashlib
import json
import re
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from flask import request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from app import app, db, csrf, limiter, admin_only, StoreItem, StoreOrder, parse_iqd_price, normalize_iraqi_mobile, notify_user, notify_admins

def pilot_ready():
    key = os.environ.get("SWIFTPAY_LIVE_API_KEY", "").strip()
    secret = os.environ.get("SWIFTPAY_LIVE_WEBHOOK_SECRET", "").strip()
    return key.startswith("spi_live_") and secret.startswith("whsec_")

def verify_signature(body, header):
    secret = os.environ.get("SWIFTPAY_LIVE_WEBHOOK_SECRET", "")
    if not secret.startswith("whsec_") or not header:
        return False
    try:
        parts = dict(part.strip().split("=", 1) for part in header.split(","))
        timestamp = int(parts["t"])
        signature = parts["v1"]
    except (KeyError, TypeError, ValueError):
        return False
    if abs(time.time() - timestamp) > 300 or not re.fullmatch("[0-9a-fA-F]{64}", signature):
        return False
    signed = str(timestamp).encode() + b"." + body
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.lower())

@app.route("/payments/swiftpay/live/webhook", methods=["POST"])
@csrf.exempt
def swiftpay_live_webhook():
    raw = request.get_data(cache=True, as_text=False)
    if not verify_signature(raw, request.headers.get("X-SwiftPay-Signature")):
        abort(400)
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        abort(400)
    if not isinstance(payload, dict):
        abort(400)
    data = payload.get("data")
    if payload.get("event") != "payment.succeeded" or not isinstance(data, dict):
        return {"ok": True}
    if data.get("isLive") is not True or data.get("status") != "SUCCEEDED":
        return {"ok": True}
    invoice_id = str(data.get("invoiceId") or "")
    if not invoice_id or len(invoice_id) > 120:
        return {"ok": True}
    try:
        amount = int(data.get("amount"))
    except (ValueError, TypeError):
        return {"ok": True}
    order = StoreOrder.query.filter_by(gateway_invoice_id=invoice_id, payment_provider="swiftpay_live").first()
    if not order or order.status in {"rejected", "refunded"} or amount != order.amount_iqd:
        return {"ok": True}
    if order.status not in {"approved", "completed"}:
        order.status = "approved"
        order.gateway_payment_id = str(data.get("paymentId") or "")[:120]
        order.transaction_id = str(data.get("gatewayTxnId") or data.get("paymentId") or "")[:250]
        notify_user(order.user_id, "تم تأكيد الدفع", f"تم دفع طلب المتجر رقم {order.id}", url_for("account"))
        notify_admins("SwiftPay LIVE", f"دفع طلب متجر رقم {order.id}", url_for("admin_store_orders"))
        db.session.commit()
    return {"ok": True}
