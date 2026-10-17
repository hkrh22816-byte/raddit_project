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

@app.route("/store/<int:item_id>/pay-live-pilot", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def store_pay_live_pilot(item_id):
    if not admin_only():
        abort(404)
    item = db.session.get(StoreItem, item_id) or abort(404)
    if not item.is_active or item.stock_status != "available":
        abort(404)
    if not pilot_ready():
        flash("إعدادات الدفع الحقيقي غير مكتملة.", "error")
        return redirect(url_for("store_detail", item_id=item_id))
    amount = item.price_iqd or parse_iqd_price(item.price)
    phone = normalize_iraqi_mobile(request.form.get("contact"))
    details = (request.form.get("details") or "").strip()
    if not amount or amount < 1 or not phone or len(details) > 2000:
        flash("أدخل رقم هاتف صحيح وتحقق من سعر المنتج.", "error")
        return redirect(url_for("store_detail", item_id=item_id))
    order = StoreOrder(user_id=current_user.id, store_item_id=item.id, amount_iqd=amount,
                       status="pending", contact=phone, details=details,
                       payment_provider="swiftpay_live")
    db.session.add(order)
    db.session.flush()
    body = {
        "customerName": (current_user.full_name or current_user.username)[:120],
        "customerPhone": phone,
        "items": [{"description": item.title[:200], "quantity": 1, "unitPrice": str(amount)}],
        "taxAmount": "0",
        "notes": f"Rabbit LIVE pilot store order #{order.id}",
    }
    api_request = Request(
        "https://api.swiftpayiq.com/api/v1/invoices",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + os.environ["SWIFTPAY_LIVE_API_KEY"].strip(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(api_request, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
        invoice = result.get("invoice") or {}
        page = result.get("payPage") or {}
        invoice_id = str(invoice.get("id") or "")
        pay_url = str(page.get("url") or "")
        parsed = urlparse(pay_url)
        if not invoice_id or len(invoice_id) > 120 or parsed.scheme != "https" or parsed.hostname != "swiftpayiq.com":
            raise ValueError("Invalid SwiftPay invoice response")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError):
        db.session.rollback()
        app.logger.warning("SwiftPay LIVE invoice creation failed")
        flash("تعذر إنشاء فاتورة الدفع. لا تحاول الدفع قبل مراجعة الخطأ.", "error")
        return redirect(url_for("store_detail", item_id=item_id))
    order.gateway_invoice_id = invoice_id
    db.session.commit()
    return redirect(pay_url, code=303)
