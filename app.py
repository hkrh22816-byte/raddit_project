from flask import Flask, render_template, redirect, url_for, request, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os
import uuid
import mimetypes
import re
import secrets
import resend
import hashlib
import hmac
import json
import time
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError
from datetime import datetime, timedelta
from urllib.parse import urlparse


app = Flask(__name__)

# Railway runs the app behind a reverse proxy.
# Trust one proxy hop so Flask sees the original client IP/protocol/host.
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)

if os.environ.get('RAILWAY_ENVIRONMENT'):
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
else:
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'rabbit-local-development-key')

# =========================
# Session / Cookie Security
# =========================
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = '__Host-rabbit_session'
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 12
app.config['WTF_CSRF_TIME_LIMIT'] = 60 * 60 * 2

# Standard token-based CSRF protection for all POST forms.
csrf = CSRFProtect(app)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///rabbit_database.db')

# بعض مزودي PostgreSQL قد يعيدون الصيغة القديمة postgres://
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# =========================
# إعدادات رفع الفيديو
# =========================
# على Railway نحفظ الملفات داخل الـ Volume الدائم.
# محلياً تبقى المجلدات الحالية كما هي.
PERSISTENT_STORAGE = os.environ.get('PERSISTENT_STORAGE_PATH')

if PERSISTENT_STORAGE:
    UPLOAD_FOLDER = os.path.join(
        PERSISTENT_STORAGE,
        'videos'
    )
else:
    UPLOAD_FOLDER = os.path.join(
        app.root_path,
        'protected_videos'
    )

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# الحد الأقصى للفيديو 1GB
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
app.config['MAX_FORM_MEMORY_SIZE'] = 2 * 1024 * 1024
app.config['MAX_FORM_PARTS'] = 100

ALLOWED_VIDEO_EXTENSIONS = {
    'mp4',
    'webm',
    'mov',
    'm4v'
}

# =========================
# إعدادات إثباتات الدفع
# =========================
if PERSISTENT_STORAGE:
    PAYMENT_PROOF_FOLDER = os.path.join(
        PERSISTENT_STORAGE,
        'payment_proofs'
    )
else:
    PAYMENT_PROOF_FOLDER = os.path.join(
        app.root_path,
        'protected_payment_proofs'
    )
os.makedirs(PAYMENT_PROOF_FOLDER, exist_ok=True)
app.config['PAYMENT_PROOF_FOLDER'] = PAYMENT_PROOF_FOLDER

ALLOWED_PROOF_EXTENSIONS = {
    'jpg', 'jpeg', 'png', 'webp', 'pdf'
}
MAX_PAYMENT_PROOF_SIZE = 10 * 1024 * 1024



db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'auth_page'
login_manager.init_app(app)

# =========================
# Rate Limiting
# =========================
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
)


# =========================
# CSRF / Security Protection
# =========================
@app.before_request
def protect_post_requests():
    if request.method == 'POST':
        if request.endpoint == 'swiftpay_webhook':
            return
        source = request.headers.get('Origin') or request.headers.get('Referer')

        if not source:
            abort(403)

        try:
            source_host = urlparse(source).netloc.lower()
        except ValueError:
            abort(403)

        if source_host != request.host.lower():
            abort(403)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('X-Permitted-Cross-Domain-Policies', 'none')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault(
        'Permissions-Policy',
        'camera=(), microphone=(), geolocation=()'
    )
    response.headers.setdefault(
        'Strict-Transport-Security',
        'max-age=63072000; includeSubDomains'
    )
    # CSP is intentionally permissive for inline CSS/JS because the current
    # templates use inline styles and scripts. We can tighten this later by
    # moving inline code to static files or adding nonces.
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'self'; "
        "object-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "media-src 'self' blob:; "
        "connect-src 'self';"
    )
    if current_user.is_authenticated:
        response.headers.setdefault('Cache-Control', 'no-store, private')
        response.headers.setdefault('Pragma', 'no-cache')
    return response


# =========================
# Models
# =========================

class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    full_name = db.Column(
        db.String(120),
        nullable=True
    )

    email = db.Column(
        db.String(254),
        unique=True,
        nullable=True
    )

    phone = db.Column(
        db.String(20),
        unique=True,
        nullable=True
    )

    email_verified = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    phone_verified = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    # Legacy contact field kept temporarily so old accounts keep working.
    email_or_phone = db.Column(
        db.String(100),
        unique=True,
        nullable=True
    )

    password = db.Column(
        db.String(200),
        nullable=False
    )

    has_paid_course = db.Column(
        db.Boolean,
        default=False
    )

    is_admin = db.Column(
        db.Boolean,
        default=False
    )


class WalletTopUp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payment_method_id = db.Column(db.Integer, db.ForeignKey('payment_method.id'), nullable=False)
    amount_iqd = db.Column(db.Integer, nullable=False)
    transaction_id = db.Column(db.String(250), default='')
    proof_filename = db.Column(db.String(250), default='')
    status = db.Column(db.String(30), default='pending', nullable=False)
    admin_note = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', backref='wallet_topups')
    payment_method = db.relationship('PaymentMethod', backref='wallet_topups')


class WalletTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(30), nullable=False)
    amount_iqd = db.Column(db.Integer, nullable=False)
    reference_type = db.Column(db.String(40), default='')
    reference_id = db.Column(db.Integer, nullable=True)
    note = db.Column(db.String(250), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref='wallet_transactions')


def wallet_balance_iqd(user_id):
    credited = db.session.query(db.func.coalesce(db.func.sum(WalletTransaction.amount_iqd), 0)).filter(
        WalletTransaction.user_id == user_id
    ).scalar()
    return int(credited or 0)


def parse_iqd_price(value):
    raw = (value or '').replace(',', '').replace('د.ع', '').replace('دينار', '').strip()
    return int(raw) if raw.isdigit() else None


class AccountingExpense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount_iqd = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(80), default='مصروف عام', nullable=False)
    note = db.Column(db.String(250), default='')
    expense_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False,
        index=True
    )

    code_hash = db.Column(
        db.String(255),
        nullable=False
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )

    attempts = db.Column(
        db.Integer,
        default=0,
        nullable=False
    )

    used = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )



class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    category = db.Column(db.String(80), nullable=False, default='خدمات رقمية')
    short_description = db.Column(db.String(280), default='')
    description = db.Column(db.Text, default='')
    price = db.Column(db.String(60), default='حسب الطلب')
    price_iqd = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    position = db.Column(db.Integer, default=1, nullable=False)


class CatalogMigration(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ServicePackage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    label = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_iqd = db.Column(db.Integer, nullable=False)
    position = db.Column(db.Integer, default=1, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    description = db.Column(db.Text, default='')
    group_key = db.Column(db.String(60), default='', nullable=False)
    service = db.relationship('Service', backref=db.backref('packages', lazy=True, cascade='all, delete-orphan'))


class StoreItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    category = db.Column(db.String(80), nullable=False, default='منتج رقمي')
    short_description = db.Column(db.String(280), default='')
    description = db.Column(db.Text, default='')
    price = db.Column(db.String(60), default='حسب العرض')
    price_iqd = db.Column(db.Integer, nullable=True)
    stock_status = db.Column(db.String(30), default='available', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    position = db.Column(db.Integer, default=1, nullable=False)


class StoreOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    store_item_id = db.Column(db.Integer, db.ForeignKey('store_item.id'), nullable=False)
    payment_method_id = db.Column(db.Integer, db.ForeignKey('payment_method.id'), nullable=True)
    amount_iqd = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), default='pending', nullable=False)
    contact = db.Column(db.String(80), default='')
    details = db.Column(db.Text, default='')
    transaction_id = db.Column(db.String(250), default='')
    refund_account = db.Column(db.String(250), default='')
    proof_filename = db.Column(db.String(250), default='')
    payment_provider = db.Column(db.String(30), default='', nullable=False)
    gateway_invoice_id = db.Column(db.String(120), default='', nullable=False)
    gateway_payment_id = db.Column(db.String(120), default='', nullable=False)
    admin_note = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref='store_orders')
    store_item = db.relationship('StoreItem', backref='orders')
    payment_method = db.relationship('PaymentMethod', backref='store_orders')


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    item_type = db.Column(db.String(20), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True)
    store_item_id = db.Column(db.Integer, db.ForeignKey('store_item.id'), nullable=True)
    package_id = db.Column(db.Integer, db.ForeignKey('service_package.id'), nullable=True)
    platform = db.Column(db.String(30), default='', nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    service = db.relationship('Service')
    store_item = db.relationship('StoreItem')
    package = db.relationship('ServicePackage')


class ServiceRequest(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(50),
        nullable=False
    )

    service_type = db.Column(
        db.String(50),
        nullable=False
    )

    details = db.Column(
        db.Text,
        nullable=False
    )

    phone = db.Column(
        db.String(20),
        nullable=False
    )


class Course(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    title = db.Column(
        db.String(180),
        nullable=False
    )

    category = db.Column(
        db.String(80),
        nullable=False
    )

    level = db.Column(
        db.String(50),
        nullable=False,
        default='مبتدئ'
    )

    price = db.Column(
        db.String(50),
        default='قريباً'
    )

    price_iqd = db.Column(
        db.Integer,
        nullable=True
    )

    instructor = db.Column(
        db.String(120),
        default='سيتم الإعلان عنه قريباً'
    )

    description = db.Column(
        db.Text,
        default=''
    )

    is_published = db.Column(
        db.Boolean,
        default=True
    )

    lessons = db.relationship(
        'Lesson',
        backref='course',
        lazy=True,
        cascade='all, delete-orphan',
        order_by='Lesson.position'
    )


class Lesson(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey('course.id'),
        nullable=False
    )

    title = db.Column(
        db.String(180),
        nullable=False
    )

    video_url = db.Column(
        db.Text,
        default=''
    )

    duration = db.Column(
        db.String(30),
        default=''
    )

    position = db.Column(
        db.Integer,
        default=1
    )

    is_preview = db.Column(
        db.Boolean,
        default=False
    )


class Enrollment(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey('course.id'),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        default='pending',
        nullable=False
    )

    user = db.relationship(
        'User',
        backref='enrollments'
    )

    course = db.relationship(
        'Course',
        backref='enrollments'
    )

    __table_args__ = (
        db.UniqueConstraint(
            'user_id',
            'course_id',
            name='unique_user_course'
        ),
    )


class LessonProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False, index=True)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref='lesson_progress_records')
    lesson = db.relationship('Lesson', backref='progress_records')
    __table_args__ = (db.UniqueConstraint('user_id', 'lesson_id', name='unique_user_lesson_progress'),)


# =========================
# Payment Methods
# =========================

class PaymentMethod(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    payment_type = db.Column(
        db.String(50),
        nullable=False,
        default='manual'
    )

    account_name = db.Column(
        db.String(150),
        default=''
    )

    account_number = db.Column(
        db.String(250),
        default=''
    )

    network = db.Column(
        db.String(100),
        default=''
    )

    instructions = db.Column(
        db.Text,
        default=''
    )

    is_active = db.Column(
        db.Boolean,
        default=True
    )

    position = db.Column(
        db.Integer,
        default=1
    )


def is_supported_manual_payment(method):
    if not method or not method.is_active:
        return False
    label = f"{method.name or ''} {method.network or ''}".casefold().replace(' ', '')
    return any(token in label for token in (
        'qicard', 'كيكارد', 'كيكارت', 'qiكارد', 'زينكاش', 'zaincash'
    ))


def get_supported_manual_payment_methods():
    return [method for method in PaymentMethod.query.filter_by(is_active=True)
            .order_by(PaymentMethod.position.asc(), PaymentMethod.id.asc()).all()
            if is_supported_manual_payment(method)]


def terms_accepted():
    return request.form.get('accept_terms') == 'yes'


def swiftpay_test_api_key():
    key = (os.environ.get('SWIFTPAY_TEST_API_KEY') or '').strip()
    if os.environ.get('SWIFTPAY_MODE', '').strip().lower() != 'test':
        return ''
    return key if key.startswith('spi_test_') else ''


def swiftpay_test_enabled_for_admin():
    return bool(admin_only() and swiftpay_test_api_key())


def normalize_iraqi_mobile(value):
    value = (value or '').translate(str.maketrans(
        '٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹',
        '01234567890123456789'
    ))
    digits = re.sub(r'\D', '', value)
    if digits.startswith('00964'):
        digits = digits[5:]
    elif digits.startswith('964'):
        digits = digits[3:]
    if digits.startswith('0'):
        digits = digits[1:]
    if len(digits) != 10 or not digits.startswith('7'):
        return ''
    return '+964' + digits


def create_swiftpay_test_invoice(order_type, order_id, customer_name,
                                 customer_phone, description, amount_iqd):
    api_key = swiftpay_test_api_key()
    if not api_key or not isinstance(amount_iqd, int) or amount_iqd < 1:
        return None

    payload = {
        'customerName': (customer_name or 'Rabbit customer')[:120],
        'customerPhone': customer_phone,
        'items': [{
            'description': (description or 'Rabbit order')[:200],
            'quantity': 1,
            'unitPrice': str(amount_iqd),
        }],
        'taxAmount': '0',
        'notes': f'Rabbit {order_type} order #{order_id} (test)',
    }
    api_request = UrlRequest(
        'https://api.swiftpayiq.com/api/v1/invoices',
        data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
        method='POST',
    )
    try:
        with urlopen(api_request, timeout=15) as response:
            result = json.loads(response.read().decode('utf-8'))
    except HTTPError as exc:
        app.logger.warning('SwiftPay test invoice request failed with HTTP %s', exc.code)
        return None
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        app.logger.warning('SwiftPay test invoice request failed')
        return None

    invoice = result.get('invoice') or {}
    pay_page = result.get('payPage') or {}
    invoice_id = str(invoice.get('id') or '')
    pay_url = str(pay_page.get('url') or '')
    parsed = urlparse(pay_url)
    if (not invoice_id or len(invoice_id) > 120 or parsed.scheme != 'https'
            or parsed.hostname != 'swiftpayiq.com'):
        app.logger.warning('SwiftPay test invoice response was incomplete or invalid')
        return None
    return invoice_id, pay_url


def verify_swiftpay_test_webhook(raw_body, signature_header):
    secret = (os.environ.get('SWIFTPAY_TEST_WEBHOOK_SECRET') or '').strip()
    if (os.environ.get('SWIFTPAY_MODE', '').strip().lower() != 'test'
            or not secret.startswith('whsec_') or not signature_header):
        return False
    parts = {}
    try:
        for item in signature_header.split(','):
            name, value = item.strip().split('=', 1)
            parts[name] = value
        timestamp = int(parts['t'])
        signature = parts['v1']
    except (KeyError, TypeError, ValueError):
        return False
    if abs(time.time() - timestamp) > 300 or not re.fullmatch(r'[0-9a-fA-F]{64}', signature):
        return False
    signed_payload = str(timestamp).encode('ascii') + b'.' + raw_body
    expected = hmac.new(secret.encode('utf-8'), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.lower())


# =========================
# Course Payments
# =========================

class ServiceOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    payment_method_id = db.Column(db.Integer, db.ForeignKey('payment_method.id'), nullable=True)
    service_package_id = db.Column(db.Integer, db.ForeignKey('service_package.id'), nullable=True)
    package_label = db.Column(db.String(120), default='')
    amount = db.Column(db.String(60), default='')
    page_url = db.Column(db.Text, default='')
    details = db.Column(db.Text, default='')
    contact = db.Column(db.String(80), default='')
    refund_account = db.Column(db.String(250), default='')
    transaction_id = db.Column(db.String(250), default='')
    proof_filename = db.Column(db.String(250), default='')
    request_attachment_filename = db.Column(db.String(250), default='')
    payment_provider = db.Column(db.String(30), default='', nullable=False)
    gateway_invoice_id = db.Column(db.String(120), default='', nullable=False)
    gateway_payment_id = db.Column(db.String(120), default='', nullable=False)
    status = db.Column(db.String(30), default='pending', nullable=False)
    admin_note = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref='service_orders')
    service = db.relationship('Service', backref='orders')
    payment_method = db.relationship('PaymentMethod', backref='service_orders')
    service_package = db.relationship('ServicePackage', backref='orders')


class CoursePayment(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id'),
        nullable=False
    )

    course_id = db.Column(
        db.Integer,
        db.ForeignKey('course.id'),
        nullable=False
    )

    enrollment_id = db.Column(
        db.Integer,
        db.ForeignKey('enrollment.id'),
        nullable=False
    )

    payment_method_id = db.Column(
        db.Integer,
        db.ForeignKey('payment_method.id'),
        nullable=False
    )

    amount = db.Column(
        db.String(50),
        default=''
    )

    transaction_id = db.Column(
        db.String(250),
        default=''
    )

    proof_filename = db.Column(
        db.String(250),
        default=''
    )

    note = db.Column(
        db.Text,
        default=''
    )

    status = db.Column(
        db.String(30),
        default='pending',
        nullable=False
    )

    admin_note = db.Column(
        db.Text,
        default=''
    )

    user = db.relationship(
        'User',
        backref='course_payments'
    )

    course = db.relationship(
        'Course',
        backref='payments'
    )

    enrollment = db.relationship(
        'Enrollment',
        backref='payments'
    )

    payment_method = db.relationship(
        'PaymentMethod',
        backref='payments'
    )


# =========================
# Login
# =========================

@login_manager.user_loader
def load_user(user_id):
    try:
        parsed_user_id = int(user_id)
    except (TypeError, ValueError):
        return None
    return db.session.get(User, parsed_user_id)


def admin_only():

    return (
        current_user.is_authenticated
        and current_user.is_admin
    )


# =========================
# Video helpers
# =========================

def allowed_video(filename):

    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower()
        in ALLOWED_VIDEO_EXTENSIONS
    )


def save_video(video_file):

    if not video_file:
        return None

    if not video_file.filename:
        return None

    if not allowed_video(video_file.filename):
        return None

    # تحقق إضافي من نوع المحتوى المعلن من المتصفح.
    # لا نعتمد عليه وحده، لكنه يمنع الملفات الواضحة غير المطابقة.
    declared_type = (video_file.mimetype or '').lower()
    guessed_type = (mimetypes.guess_type(video_file.filename)[0] or '').lower()
    if declared_type and not declared_type.startswith('video/'):
        return None
    if guessed_type and not guessed_type.startswith('video/'):
        return None

    original_name = secure_filename(
        video_file.filename
    )

    extension = original_name.rsplit(
        '.',
        1
    )[1].lower()

    unique_name = (
        uuid.uuid4().hex
        + '.'
        + extension
    )

    save_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        unique_name
    )

    video_file.save(save_path)

    return unique_name


# =========================
# Payment proof helpers
# =========================
def allowed_payment_proof(filename):
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower()
        in ALLOWED_PROOF_EXTENSIONS
    )


def save_payment_proof(proof_file):
    if not proof_file or not proof_file.filename:
        return None

    if not allowed_payment_proof(proof_file.filename):
        return None

    # إثبات الدفع يجب أن يكون صورة أو PDF بحسب نوع المحتوى المعلن.
    declared_type = (proof_file.mimetype or '').lower()
    guessed_type = (mimetypes.guess_type(proof_file.filename)[0] or '').lower()
    allowed_declared = declared_type.startswith('image/') or declared_type == 'application/pdf'
    allowed_guessed = guessed_type.startswith('image/') or guessed_type == 'application/pdf'
    if declared_type and not allowed_declared:
        return None
    if guessed_type and not allowed_guessed:
        return None

    original_name = secure_filename(proof_file.filename)
    extension = original_name.rsplit('.', 1)[1].lower()
    unique_name = uuid.uuid4().hex + '.' + extension
    save_path = os.path.join(
        app.config['PAYMENT_PROOF_FOLDER'],
        unique_name
    )
    proof_file.save(save_path)
    return unique_name


def save_service_request_image(image_file):
    """Save a private image attachment for an account-recovery service order."""
    if not image_file or not image_file.filename:
        return None
    original_name = secure_filename(image_file.filename)
    if not original_name or '.' not in original_name:
        return None
    extension = original_name.rsplit('.', 1)[1].lower()
    if extension not in {'jpg', 'jpeg', 'png', 'webp'}:
        return None
    declared_type = (image_file.mimetype or '').lower()
    guessed_type = (mimetypes.guess_type(original_name)[0] or '').lower()
    if declared_type and not declared_type.startswith('image/'):
        return None
    if guessed_type and not guessed_type.startswith('image/'):
        return None
    payload = image_file.stream.read(2 * 1024 * 1024 + 1)
    if not payload or len(payload) > 2 * 1024 * 1024:
        return None
    image_file.stream.seek(0)
    unique_name = uuid.uuid4().hex + '.' + extension
    save_path = os.path.join(app.config['PAYMENT_PROOF_FOLDER'], unique_name)
    image_file.save(save_path)
    return unique_name


@app.route('/protected-video/<int:lesson_id>')
def protected_video(lesson_id):

    lesson = db.session.get(
        Lesson,
        lesson_id
    ) or abort(404)

    if current_user.is_authenticated and current_user.is_admin:
        has_access = True

    elif lesson.is_preview:
        has_access = True

    else:
        enrollment = Enrollment.query.filter_by(
            user_id=current_user.id,
            course_id=lesson.course_id
        ).first()

        has_access = (
            enrollment is not None
            and enrollment.status == 'approved'
        )

    if not has_access:
        abort(403)

    if not lesson.video_url:
        abort(404)

    filename = os.path.basename(
        lesson.video_url
    )

    file_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        filename
    )

    if not os.path.isfile(file_path):
        abort(404)

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        conditional=True
    )


# =========================
# Courses Seed
# =========================

SEED = [

    (
        'إعلانات Meta من الصفر إلى الاحتراف',
        'التسويق',
        'مبتدئ',
        'تعلم كيفية إطلاق حملات إعلانية ناجحة على فيسبوك وإنستغرام.'
    ),

    (
        'إعلانات TikTok والتسويق عبر تيك توك',
        'التسويق',
        'متوسط',
        'تعلم بناء الحملات الإعلانية وقراءة النتائج وتحسينها.'
    ),

    (
        'إدارة صفحات السوشيال ميديا',
        'السوشيال ميديا',
        'مبتدئ',
        'تنظيم وإدارة الحسابات التجارية وجدولة المحتوى باحترافية.'
    ),

    (
        'صناعة المحتوى بالموبايل',
        'السوشيال ميديا',
        'مبتدئ',
        'تصوير وإنتاج محتوى مرئي جذاب باستخدام الهاتف.'
    ),

    (
        'مونتاج CapCut من الصفر إلى الاحتراف',
        'التصميم',
        'مبتدئ',
        'مونتاج الفيديوهات القصيرة والريلز خطوة بخطوة.'
    ),

    (
        'التصميم باستخدام Canva',
        'التصميم',
        'مبتدئ',
        'تصميم الإعلانات والمنشورات والهويات البصرية بسهولة.'
    ),

    (
        'Photoshop من الصفر',
        'التصميم',
        'متقدم',
        'أساسيات التعديل والدمج وبناء التصاميم الإعلانية.'
    ),

    (
        'الذكاء الاصطناعي للعمل والدراسة',
        'الذكاء الاصطناعي',
        'مبتدئ',
        'استخدام أدوات الذكاء الاصطناعي لرفع الإنتاجية.'
    ),

    (
        'ChatGPT لصناعة المحتوى والتسويق',
        'الذكاء الاصطناعي',
        'متوسط',
        'استخدام ChatGPT للأفكار والسيناريوهات والخطط التسويقية.'
    ),

    (
        'إنشاء متجر إلكتروني',
        'البرمجة',
        'متوسط',
        'بناء متجر إلكتروني واستقبال طلبات الزبائن.'
    ),

    (
        'كيف تبدأ مشروع بيع أونلاين في العراق',
        'الأعمال',
        'مبتدئ',
        'من اختيار المنتج إلى التسويق والتوصيل داخل العراق.'
    ),

    (
        'التصوير الإعلاني بالموبايل',
        'التصميم',
        'متوسط',
        'زوايا وإضاءة تصوير المنتجات بالموبايل.'
    ),

    (
        'التعليق الصوتي وصناعة الفيديو',
        'السوشيال ميديا',
        'متوسط',
        'تسجيل صوت واضح وإنتاج فيديو احترافي.'
    ),

    (
        'Excel من الصفر للعمل',
        'المهارات المكتبية',
        'مبتدئ',
        'الجداول والمعادلات والتقارير التي يحتاجها الموظف.'
    ),

    (
        'المحاسبة لأصحاب المشاريع الصغيرة',
        'الأعمال',
        'مبتدئ',
        'فهم الأرباح والخسائر والمصاريف وإدارة المشروع.'
    ),

    (
        'اللغة الإنجليزية للعمل والمحادثة',
        'اللغات',
        'مبتدئ',
        'محادثات ومصطلحات عملية للاستخدام في بيئة العمل.'
    )

]


def seed_courses():

    if Course.query.count() == 0:

        for title, cat, level, desc in SEED:

            db.session.add(
                Course(
                    title=title,
                    category=cat,
                    level=level,
                    description=desc
                )
            )

        db.session.commit()



SERVICE_SEED = []

STORE_SEED = [
    ('حسابات رقمية متاحة للبيع', 'حسابات', 'عروض حسابات رقمية متاحة وفق شروط المنصة.', 'يتم عرض التفاصيل المتاحة لكل حساب بشكل واضح. لا يتم تجاوز حماية المنصات أو أنظمة إثبات الملكية.', 'حسب العرض'),
    ('باقات وتصاميم جاهزة', 'منتجات رقمية', 'حزم رقمية جاهزة للمشاريع وصفحات السوشيال.', 'منتجات رقمية وعروض جاهزة يمكن شراؤها حسب المتوفر.', 'حسب العرض'),
]


def seed_services_and_store():
    # Clear trial records once, retaining the configured admin and site content.
    cleanup_key = 'fresh_site_reset_v2'
    if db.session.get(CatalogMigration, cleanup_key) is None:
        admin_username = os.environ.get('ADMIN_USERNAME')
        admin_user = User.query.filter_by(username=admin_username).first() if admin_username else None
        if admin_user is None:
            admin_user = User.query.filter_by(is_admin=True).order_by(User.id.asc()).first()
        if admin_user is not None:
            admin_user.is_admin = True
            proof_files = []
            for model in (WalletTopUp, StoreOrder, ServiceOrder, CoursePayment):
                proof_files.extend(
                    row[0] for row in db.session.query(model.proof_filename)
                    .filter(model.proof_filename != '')
                    .all() if row[0]
                )

            ServiceRequest.query.delete(synchronize_session=False)
            CoursePayment.query.delete(synchronize_session=False)
            Enrollment.query.delete(synchronize_session=False)
            LessonProgress.query.delete(synchronize_session=False)
            ServiceOrder.query.delete(synchronize_session=False)
            StoreOrder.query.delete(synchronize_session=False)
            WalletTopUp.query.delete(synchronize_session=False)
            WalletTransaction.query.delete(synchronize_session=False)
            PasswordResetOTP.query.delete(synchronize_session=False)
            ServicePackage.query.delete(synchronize_session=False)
            Service.query.delete(synchronize_session=False)
            User.query.filter(User.id != admin_user.id).delete(synchronize_session=False)
            db.session.add(CatalogMigration(key=cleanup_key))
            db.session.commit()

            for filename in proof_files:
                safe_name = os.path.basename(filename)
                proof_path = os.path.join(app.config['PAYMENT_PROOF_FOLDER'], safe_name)
                try:
                    if os.path.isfile(proof_path):
                        os.remove(proof_path)
                except OSError:
                    app.logger.warning('Could not remove old payment proof file %s', safe_name)

    if StoreItem.query.count() == 0:
        for i, item in enumerate(STORE_SEED, 1):
            db.session.add(StoreItem(
                title=item[0],
                category=item[1],
                short_description=item[2],
                description=item[3],
                price=item[4],
                position=i
            ))
    db.session.flush()


    db.session.commit()

@app.context_processor
def inject_wallet_balance():
    if current_user.is_authenticated:
        return {
            'header_wallet_balance': f'{wallet_balance_iqd(current_user.id):,} د.ع',
            'header_cart_count': CartItem.query.filter_by(user_id=current_user.id).count()
        }
    return {'header_wallet_balance': None, 'header_cart_count': 0}


FOLLOWER_PLATFORMS = {
    'instagram': 'إنستغرام',
    'facebook': 'فيسبوك',
    'tiktok': 'تيك توك',
    'telegram': 'تليگرام',
}

ACCOUNT_RECOVERY_SERVICE_TITLE = 'استرجاع حسابات فيسبوك وإنستغرام المعطّلة'
ACCOUNT_RECOVERY_PLATFORMS = {
    'facebook': 'فيسبوك',
    'instagram': 'إنستغرام',
}


def is_account_recovery_service(service):
    return bool(service and service.title == ACCOUNT_RECOVERY_SERVICE_TITLE)


def seed_account_recovery_service():
    service = Service.query.filter_by(title=ACCOUNT_RECOVERY_SERVICE_TITLE).first()
    if service is None:
        next_position = (db.session.query(db.func.max(Service.position)).scalar() or 0) + 1
        service = Service(
            title=ACCOUNT_RECOVERY_SERVICE_TITLE,
            category='استعادة الحسابات',
            short_description='مراجعة طلبات استعادة حسابات فيسبوك وإنستغرام ومعالجة تقييد الرسائل.',
            description=(
                'اختر المنصة ونوع المشكلة، ثم أرفق صورة رسالة التعطيل أو الحظر واكتب اسم المستخدم ورقم التواصل. '
                'لا ترسل كلمة المرور أو رمز التحقق. مدة العمل المذكورة هي مدة متابعة الطلب، '
                'أما استعادة الحساب فتعتمد على قرار المنصة ولا يمكن ضمان قبولها.'
            ),
            price='تبدأ من 25,000 د.ع',
            price_iqd=25000,
            is_active=True,
            position=next_position,
        )
        db.session.add(service)
        db.session.flush()
    tiers = [
        ('حساب معطّل نهائيًا', 150000, 'مدة العمل: من يوم إلى أسبوع.'),
        ('حساب معطّل عاديًا', 75000, 'مدة المعالجة تُحدد بعد مراجعة الحالة.'),
        ('حظر إرسال الرسائل', 25000, 'مدة العمل: بحد أقصى 24 ساعة.'),
    ]
    existing = {package.label for package in ServicePackage.query.filter_by(service_id=service.id).all()}
    next_package_position = (db.session.query(db.func.max(ServicePackage.position))
                             .filter_by(service_id=service.id).scalar() or 0) + 1
    for offset, (label, price_iqd, description) in enumerate(tiers):
        if label in existing:
            continue
        db.session.add(ServicePackage(
            service_id=service.id,
            label=label,
            quantity=1,
            price_iqd=price_iqd,
            position=next_package_position + offset,
            is_active=True,
            description=description,
        ))
    db.session.commit()

SOCIAL_PACKAGE_GROUPS = {
    'facebook_followers': {'platform': 'facebook', 'label': 'متابعين', 'unit': 'متابع'},
    'telegram_members': {'platform': 'telegram', 'label': 'أعضاء', 'unit': 'عضو'},
    'tiktok_followers_fast': {'platform': 'tiktok', 'label': 'متابعين — سرعة عالية', 'unit': 'متابع'},
    'tiktok_followers_slow': {'platform': 'tiktok', 'label': 'متابعين — سرعة بطيئة', 'unit': 'متابع'},
    'tiktok_likes': {'platform': 'tiktok', 'label': 'لايكات فيديو — ثابتة مع ضمان', 'unit': 'لايك'},
    'tiktok_views': {'platform': 'tiktok', 'label': 'مشاهدات فيديو', 'unit': 'مشاهدة'},
    'instagram_followers': {'platform': 'instagram', 'label': 'متابعين — ضمان شهر', 'unit': 'متابع'},
    'instagram_likes': {'platform': 'instagram', 'label': 'لايكات', 'unit': 'لايك'},
    'instagram_reel_views': {'platform': 'instagram', 'label': 'مشاهدات ريلز — ثابتة وسريعة', 'unit': 'مشاهدة'},
}

SOCIAL_PACKAGE_GROUP_CHOICES = [
    ('facebook_followers', 'فيسبوك — متابعين'),
    ('instagram_followers', 'إنستغرام — متابعين (ضمان شهر)'),
    ('instagram_likes', 'إنستغرام — لايكات'),
    ('instagram_reel_views', 'إنستغرام — مشاهدات ريلز'),
    ('tiktok_followers_fast', 'تيك توك — متابعين (سرعة عالية)'),
    ('tiktok_followers_slow', 'تيك توك — متابعين (سرعة بطيئة)'),
    ('tiktok_likes', 'تيك توك — لايكات (ضمان)'),
    ('tiktok_views', 'تيك توك — مشاهدات'),
    ('telegram_members', 'تليگرام — أعضاء'),
]


def social_package_group(package):
    return SOCIAL_PACKAGE_GROUPS.get(package.group_key or '')


def is_follower_service(service):
    marker = f"{service.title or ''} {service.category or ''}".casefold()
    return 'متابع' in marker or 'followers' in marker


def cart_entry(item):
    if item.item_type == 'service':
        service = db.session.get(Service, item.service_id) if item.service_id else None
        if not service or not service.is_active:
            return None
        active_packages = ServicePackage.query.filter_by(
            service_id=service.id, is_active=True
        ).all()
        package = db.session.get(ServicePackage, item.package_id) if item.package_id else None
        if active_packages and (not package or package.service_id != service.id or not package.is_active):
            return None
        price = package.price_iqd if package else (service.price_iqd or parse_iqd_price(service.price))
        if not price or price < 1:
            return None
        follower = is_follower_service(service)
        if follower and item.platform not in FOLLOWER_PLATFORMS:
            return None
        package_group = social_package_group(package) if package else None
        if package_group and package_group['platform'] != item.platform:
            return None
        group_label = package_group['label'] if package_group else ''
        return {
            'type': 'service', 'title': service.title,
            'label': f'{group_label} — {package.label}' if package_group else (package.label if package else ''),
            'package_quantity': package.quantity if package else 0,
            'package_unit': package_group['unit'] if package_group else 'متابع',
            'package_group': group_label,
            'platform': FOLLOWER_PLATFORMS.get(item.platform, ''),
            'unit_price': price, 'quantity': 1, 'line_total': price,
            'url': url_for('service_detail', service_id=service.id),
        }
    if item.item_type == 'store':
        product = db.session.get(StoreItem, item.store_item_id) if item.store_item_id else None
        if not product or not product.is_active or product.stock_status != 'available':
            return None
        price = product.price_iqd or parse_iqd_price(product.price)
        quantity = min(99, max(1, item.quantity or 1))
        if not price or price < 1:
            return None
        return {
            'type': 'store', 'title': product.title, 'label': '', 'package_quantity': 0,
            'platform': '', 'unit_price': price, 'quantity': quantity,
            'line_total': price * quantity, 'url': url_for('store_detail', item_id=product.id),
        }
    return None


# =========================
# Home
# =========================

@app.route('/')
def home():

    return render_template(
        'index.html'
    )


@app.route('/support')
def support():
    return render_template('support.html')



@app.route('/services')
def services():
    items = Service.query.filter_by(is_active=True).order_by(Service.position.asc(), Service.id.asc()).all()
    categories = []
    for item in items:
        category = (item.category or 'خدمات أخرى').strip()
        group = next((entry for entry in categories if entry['name'] == category), None)
        if group is None:
            group = {'name': category, 'services': []}
            categories.append(group)
        group['services'].append(item)
    return render_template('services.html', services=items, categories=categories)


@app.route('/services/category/<path:category>')
def service_category(category):
    items = Service.query.filter_by(is_active=True, category=category).order_by(
        Service.position.asc(), Service.id.asc()
    ).all()
    if not items:
        abort(404)
    return render_template('service_category.html', category=category, services=items)


@app.route('/services/<int:service_id>')
def service_detail(service_id):
    item = db.session.get(Service, service_id) or abort(404)
    if not item.is_active and not admin_only():
        abort(404)
    payment_methods = get_supported_manual_payment_methods()
    packages = ServicePackage.query.filter_by(service_id=item.id, is_active=True).order_by(ServicePackage.position.asc(), ServicePackage.id.asc()).all()
    grouped_packages = []
    for group_key, group_info in SOCIAL_PACKAGE_GROUPS.items():
        group_items = [package for package in packages if package.group_key == group_key]
        if group_items:
            grouped_packages.append({
                'key': group_key,
                'platform': group_info['platform'],
                'label': group_info['label'],
                'unit': group_info['unit'],
                'packages': group_items,
            })
    grouped_package_service = bool(packages and len(grouped_packages) and all(package.group_key in SOCIAL_PACKAGE_GROUPS for package in packages))
    package_platforms = []
    for group in grouped_packages:
        if group['platform'] not in [platform['key'] for platform in package_platforms]:
            package_platforms.append({'key': group['platform'], 'name': FOLLOWER_PLATFORMS[group['platform']]})
    platform_order = {'facebook': 0, 'instagram': 1, 'tiktok': 2, 'telegram': 3}
    package_platforms.sort(key=lambda platform: platform_order.get(platform['key'], 99))
    return render_template(
        'service_detail.html', service=item, payment_methods=payment_methods,
        packages=packages, follower_service=is_follower_service(item),
        account_recovery_service=is_account_recovery_service(item),
        follower_platforms=FOLLOWER_PLATFORMS,
        grouped_packages=grouped_packages,
        grouped_package_service=grouped_package_service,
        package_platforms=package_platforms,
        swiftpay_test_enabled=swiftpay_test_enabled_for_admin()
    )


@app.route('/services/<int:service_id>/pay-test', methods=['POST'])
@login_required
@limiter.limit('20 per hour')
def service_pay_test(service_id):
    item = db.session.get(Service, service_id) or abort(404)
    if not item.is_active:
        abort(404)
    if not admin_only():
        abort(404)
    if not swiftpay_test_api_key():
        flash('الدفع التجريبي غير مضبوط حالياً.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))

    contact = normalize_iraqi_mobile(request.form.get('contact'))
    page_url = (request.form.get('page_url') or '').strip()
    details = (request.form.get('details') or '').strip()
    platform = (request.form.get('platform') or '').strip().lower()
    if not contact:
        flash('اكتب رقم موبايل عراقي صحيح حتى تُنشأ فاتورة الاختبار.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))
    if not page_url or len(page_url) > 1000 or len(details) > 3000:
        flash('أكمل رابط الحساب أو المشروع وتأكد من طول التفاصيل.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))
    parsed_page_url = urlparse(page_url)
    if parsed_page_url.scheme not in {'http', 'https'} or not parsed_page_url.netloc:
        flash('رابط الحساب أو المشروع غير صحيح.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))

    package = None
    if item.packages:
        try:
            package_id = int(request.form.get('package_id') or 0)
        except ValueError:
            package_id = 0
        package = db.session.get(ServicePackage, package_id)
        if not package or package.service_id != item.id or not package.is_active:
            flash('اختر الباقة المطلوبة.', 'error')
            return redirect(url_for('service_detail', service_id=item.id))
        amount_iqd = package.price_iqd
        package_label = package.label
        group = social_package_group(package)
        if group:
            if platform != group['platform']:
                flash('اختار المنصة ونوع الخدمة المطابقين للباقة.', 'error')
                return redirect(url_for('service_detail', service_id=item.id))
            package_label = f"{group['label']} — {package.label}"
            details = f"المنصة: {FOLLOWER_PLATFORMS[platform]}\nنوع الخدمة: {group['label']}\nالمطلوب: {package.quantity:,} {group['unit']}\n{details}".strip()
    else:
        amount_iqd = item.price_iqd or parse_iqd_price(item.price)
        package_label = ''
    if not amount_iqd or amount_iqd < 1:
        flash('حدد سعر الخدمة بالدينار قبل تجربة الدفع.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))

    order = ServiceOrder(
        user_id=current_user.id,
        service_id=item.id,
        service_package_id=package.id if package else None,
        package_label=package_label,
        amount=f'{amount_iqd:,} د.ع',
        page_url=page_url,
        details=details,
        contact=contact,
        status='pending',
        payment_provider='swiftpay_test',
    )
    db.session.add(order)
    db.session.flush()
    invoice = create_swiftpay_test_invoice(
        'service', order.id,
        current_user.full_name or current_user.username,
        contact,
        f'{item.title}{": " + package_label if package_label else ""}',
        amount_iqd,
    )
    if not invoice:
        db.session.rollback()
        flash('تعذر إنشاء فاتورة الاختبار. تأكد من إعداد مفتاح SwiftPay التجريبي.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))
    order.gateway_invoice_id = invoice[0]
    db.session.commit()
    return redirect(invoice[1], code=303)


@app.route('/services/<int:service_id>/buy', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def service_buy(service_id):
    item = db.session.get(Service, service_id) or abort(404)
    if not item.is_active:
        abort(404)

    account_recovery_service = is_account_recovery_service(item)
    page_url = ((request.form.get('account_username') if account_recovery_service else request.form.get('page_url')) or '').strip()
    details = (request.form.get('details') or '').strip()
    platform = (request.form.get('platform') or '').strip().lower()
    if is_follower_service(item):
        if platform not in FOLLOWER_PLATFORMS:
            flash('اختر المنصة المطلوبة لزيادة المتابعين.', 'error')
            return redirect(url_for('service_detail', service_id=item.id))
        details = f"المنصة: {FOLLOWER_PLATFORMS[platform]}\n{details}".strip()
    elif account_recovery_service:
        if platform not in ACCOUNT_RECOVERY_PLATFORMS:
            flash('اختر فيسبوك أو إنستغرام.', 'error')
            return redirect(url_for('service_detail', service_id=item.id))
        if not page_url or len(page_url) > 100:
            flash('اكتب اسم المستخدم للحساب.', 'error')
            return redirect(url_for('service_detail', service_id=item.id))
        details = f"المنصة: {ACCOUNT_RECOVERY_PLATFORMS[platform]}"
    contact = (request.form.get('contact') or '').strip()
    refund_account = (request.form.get('refund_account') or '').strip()
    transaction_id = (request.form.get('transaction_id') or '').strip()
    package = None
    package_label = ''
    amount = item.price
    if item.packages:
        try:
            package_id = int(request.form.get('package_id') or 0)
        except ValueError:
            package_id = 0
        package = db.session.get(ServicePackage, package_id)
        if not package or package.service_id != item.id or not package.is_active:
            flash('اختر الباقة المطلوبة.', 'error')
            return redirect(url_for('service_detail', service_id=service_id))
        package_label = package.label
        amount = f"{package.price_iqd:,} د.ع"
        group = social_package_group(package)
        if group and group['platform'] != platform:
            flash('اختار المنصة ونوع الخدمة المطابقين للباقة.', 'error')
            return redirect(url_for('service_detail', service_id=service_id))
        if group:
            package_label = f"{group['label']} — {package.label}"
            details = f"نوع الخدمة: {group['label']}\nالمطلوب: {package.quantity:,} {group['unit']}\n{details}".strip()

    try:
        payment_method_id = int(request.form.get('payment_method_id') or 0)
    except ValueError:
        payment_method_id = 0

    method = db.session.get(PaymentMethod, payment_method_id)
    if not is_supported_manual_payment(method):
        flash('اختر كي كارد أو زين كاش كطريقة دفع.', 'error')
        return redirect(url_for('service_detail', service_id=service_id))

    if not page_url or not contact or not refund_account or not transaction_id:
        flash('أكمل بيانات الحساب والدفع والتواصل.', 'error')
        return redirect(url_for('service_detail', service_id=service_id))

    if len(page_url) > 1000 or len(details) > 3000 or len(contact) > 80 or len(refund_account) > 250 or len(transaction_id) > 250:
        flash('بعض البيانات أطول من الحد المسموح.', 'error')
        return redirect(url_for('service_detail', service_id=service_id))

    attachment_filename = ''
    if account_recovery_service:
        attachment_filename = save_service_request_image(request.files.get('deactivation_screenshot')) or ''
        if not attachment_filename:
            flash('ارفع صورة رسالة التعطيل أو الحظر بصيغة JPG أو PNG أو WebP وبحجم لا يتجاوز 2 MB.', 'error')
            return redirect(url_for('service_detail', service_id=item.id))

    proof = save_payment_proof(request.files.get('payment_proof'))
    if not proof:
        if attachment_filename:
            try:
                os.remove(os.path.join(app.config['PAYMENT_PROOF_FOLDER'], attachment_filename))
            except OSError:
                pass
        flash('ارفع إثبات دفع بصيغة صورة أو PDF.', 'error')
        return redirect(url_for('service_detail', service_id=service_id))

    order = ServiceOrder(
        user_id=current_user.id,
        service_id=item.id,
        payment_method_id=method.id,
        service_package_id=package.id if package else None,
        package_label=package_label,
        amount=amount,
        page_url=page_url,
        details=details,
        contact=contact,
        refund_account=refund_account,
        transaction_id=transaction_id,
        proof_filename=proof,
        request_attachment_filename=attachment_filename,
        status='pending'
    )
    db.session.add(order)
    db.session.commit()
    flash('تم استلام طلب الخدمة والدفع للمراجعة.', 'success')
    return redirect(url_for('account'))


@app.route('/services/<int:service_id>/buy-wallet', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def service_buy_wallet(service_id):
    item = db.session.get(Service, service_id) or abort(404)
    flash('الدفع متاح حالياً يدوياً عبر كي كارد أو زين كاش.', 'error')
    return redirect(url_for('service_detail', service_id=item.id))

@app.route('/store')
def store():
    items = StoreItem.query.filter_by(is_active=True).order_by(StoreItem.position.asc(), StoreItem.id.asc()).all()
    return render_template('store.html', items=items)

@app.route('/store/<int:item_id>')
def store_detail(item_id):
    item = db.session.get(StoreItem, item_id) or abort(404)
    if not item.is_active:
        abort(404)
    return render_template('store_detail.html', item=item,
                           price_iqd=item.price_iqd or parse_iqd_price(item.price),
                           payment_methods=get_supported_manual_payment_methods(),
                           swiftpay_test_enabled=swiftpay_test_enabled_for_admin())


@app.route('/store/<int:item_id>/pay-test', methods=['POST'])
@login_required
@limiter.limit('20 per hour')
def store_pay_test(item_id):
    item = db.session.get(StoreItem, item_id) or abort(404)
    if not item.is_active or item.stock_status != 'available':
        abort(404)
    if not admin_only():
        abort(404)
    if not swiftpay_test_api_key():
        flash('الدفع التجريبي غير مضبوط حالياً.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))

    amount_iqd = item.price_iqd or parse_iqd_price(item.price)
    contact = normalize_iraqi_mobile(request.form.get('contact'))
    details = (request.form.get('details') or '').strip()
    if not amount_iqd or amount_iqd < 1:
        flash('حدد سعر المنتج بالدينار قبل تجربة الدفع.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    if not contact:
        flash('اكتب رقم موبايل عراقي صحيح حتى تُنشأ فاتورة الاختبار.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    if len(details) > 2000:
        flash('التفاصيل أطول من الحد المسموح.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))

    order = StoreOrder(
        user_id=current_user.id,
        store_item_id=item.id,
        amount_iqd=amount_iqd,
        status='pending',
        contact=contact,
        details=details,
        payment_provider='swiftpay_test',
    )
    db.session.add(order)
    db.session.flush()
    invoice = create_swiftpay_test_invoice(
        'store', order.id,
        current_user.full_name or current_user.username,
        contact,
        item.title,
        amount_iqd,
    )
    if not invoice:
        db.session.rollback()
        flash('تعذر إنشاء فاتورة الاختبار. تأكد من إعداد مفتاح SwiftPay التجريبي.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    order.gateway_invoice_id = invoice[0]
    db.session.commit()
    return redirect(invoice[1], code=303)


@app.route('/store/<int:item_id>/buy', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def store_buy(item_id):
    item = db.session.get(StoreItem, item_id) or abort(404)
    if not item.is_active or item.stock_status != 'available':
        abort(404)
    amount_iqd = item.price_iqd or parse_iqd_price(item.price)
    if not amount_iqd:
        flash('السعر غير محدد حالياً. تواصل ويانا لمعرفة السعر.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    try:
        quantity = min(99, max(1, int(request.form.get('quantity') or 1)))
    except (TypeError, ValueError):
        quantity = 1
    amount_iqd *= quantity
    try:
        method_id = int(request.form.get('payment_method_id') or 0)
    except ValueError:
        method_id = 0
    method = db.session.get(PaymentMethod, method_id)
    if not is_supported_manual_payment(method):
        flash('اختر كي كارد أو زين كاش كطريقة دفع.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    contact = (request.form.get('contact') or '').strip()
    details = (request.form.get('details') or '').strip()
    transaction_id = (request.form.get('transaction_id') or '').strip()
    refund_account = (request.form.get('refund_account') or '').strip()
    if not contact or not transaction_id or not refund_account:
        flash('أكمل رقم التواصل ورقم التحويل وحساب الاسترجاع.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    if len(contact) > 80 or len(details) > 2000 or len(transaction_id) > 250 or len(refund_account) > 250:
        flash('بعض البيانات أطول من الحد المسموح.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    proof = save_payment_proof(request.files.get('payment_proof'))
    if not proof:
        flash('ارفع إثبات الدفع بصيغة صورة أو PDF.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    if quantity > 1:
        details = f"الكمية: {quantity}\n{details}".strip()
    db.session.add(StoreOrder(
        user_id=current_user.id, store_item_id=item.id,
        payment_method_id=method.id, amount_iqd=amount_iqd,
        status='pending', contact=contact, details=details,
        transaction_id=transaction_id, refund_account=refund_account,
        proof_filename=proof
    ))
    db.session.commit()
    flash('وصل طلبك وإثبات الدفع. الطلب بانتظار مراجعة الإدارة.', 'success')
    return redirect(url_for('account'))


@app.route('/payments/swiftpay/test/webhook', methods=['POST'])
@csrf.exempt
def swiftpay_webhook():
    raw_body = request.get_data(cache=True, as_text=False)
    if not verify_swiftpay_test_webhook(
            raw_body, request.headers.get('X-SwiftPay-Signature')):
        abort(400)
    try:
        payload = json.loads(raw_body.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        abort(400)

    event = payload.get('event') if isinstance(payload, dict) else None
    data = payload.get('data') if isinstance(payload, dict) else None
    if event != 'invoice.paid' or not isinstance(data, dict):
        return {'ok': True}
    if (data.get('isLive') is not False or data.get('status') != 'SUCCEEDED'
            or not data.get('invoiceId')):
        return {'ok': True}
    try:
        paid_amount = int(data.get('amount'))
    except (TypeError, ValueError):
        return {'ok': True}

    invoice_id = str(data['invoiceId'])[:120]
    order = ServiceOrder.query.filter_by(
        gateway_invoice_id=invoice_id, payment_provider='swiftpay_test'
    ).first()
    if order:
        expected_amount = parse_iqd_price(order.amount)
        if order.status in {'rejected', 'refunded'} or paid_amount != expected_amount:
            return {'ok': True}
        if order.status not in {'approved', 'completed'}:
            order.status = 'approved'
            order.gateway_payment_id = str(data.get('paymentId') or '')[:120]
            order.transaction_id = str(data.get('gatewayTxnId') or data.get('paymentId') or '')[:250]
            db.session.commit()
        return {'ok': True}

    order = StoreOrder.query.filter_by(
        gateway_invoice_id=invoice_id, payment_provider='swiftpay_test'
    ).first()
    if order:
        if order.status in {'rejected', 'refunded'} or paid_amount != order.amount_iqd:
            return {'ok': True}
        if order.status not in {'approved', 'completed'}:
            order.status = 'approved'
            order.gateway_payment_id = str(data.get('paymentId') or '')[:120]
            order.transaction_id = str(data.get('gatewayTxnId') or data.get('paymentId') or '')[:250]
            db.session.commit()
    return {'ok': True}


@app.route('/store/<int:item_id>/buy-wallet', methods=['POST'])
@login_required
def store_buy_wallet(item_id):
    item = db.session.get(StoreItem, item_id) or abort(404)
    flash('الدفع متاح حالياً يدوياً عبر كي كارد أو زين كاش.', 'error')
    return redirect(url_for('store_detail', item_id=item.id))

@app.route('/cart')
@login_required
def cart():
    rows = CartItem.query.filter_by(user_id=current_user.id).order_by(CartItem.created_at.asc(), CartItem.id.asc()).all()
    entries = [{'data': cart_entry(row), 'row': row} for row in rows]
    total_iqd = sum(entry['data']['line_total'] for entry in entries if entry['data'])
    payment_methods = get_supported_manual_payment_methods()
    return render_template('cart.html', entries=entries, total_iqd=total_iqd,
                           payment_methods=payment_methods)


@app.route('/cart/add/service/<int:service_id>', methods=['POST'])
@login_required
@limiter.limit('30 per hour')
def cart_add_service(service_id):
    item = db.session.get(Service, service_id) or abort(404)
    if not item.is_active:
        abort(404)
    if is_account_recovery_service(item):
        flash('خدمة استعادة الحساب تُشترى مباشرة حتى ترفق صورة الحالة.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))
    packages = ServicePackage.query.filter_by(service_id=item.id, is_active=True).filter(ServicePackage.price_iqd > 0).all()
    package = None
    if packages:
        try:
            package = db.session.get(ServicePackage, int(request.form.get('package_id') or 0))
        except (TypeError, ValueError):
            package = None
        if not package or package.service_id != item.id or not package.is_active:
            flash('اختار الباقة قبل إضافتها للسلة.', 'error')
            return redirect(url_for('service_detail', service_id=item.id))
    elif not (item.price_iqd or parse_iqd_price(item.price)):
        flash('هذه الخدمة تحتاج تسعيراً حسب تفاصيل المشروع، لذلك ما تنضاف للسلة حالياً.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))

    platform = (request.form.get('platform') or '').strip().lower()
    if is_follower_service(item) and platform not in FOLLOWER_PLATFORMS:
        flash('اختار منصة التواصل قبل إضافة الخدمة للسلة.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))
    group = social_package_group(package) if package else None
    if group and group['platform'] != platform:
        flash('اختار المنصة ونوع الخدمة المطابقين للباقة.', 'error')
        return redirect(url_for('service_detail', service_id=item.id))
    existing = CartItem.query.filter_by(
        user_id=current_user.id, item_type='service', service_id=item.id,
        package_id=package.id if package else None, platform=platform
    ).first()
    if not existing:
        db.session.add(CartItem(user_id=current_user.id, item_type='service',
                                service_id=item.id, package_id=package.id if package else None,
                                platform=platform, quantity=1))
    db.session.commit()
    flash('انضافت الخدمة للسلة. تگدر تكمل التسوق أو تشتريها من السلة.', 'success')
    return redirect(url_for('service_detail', service_id=item.id))


@app.route('/cart/add/store/<int:item_id>', methods=['POST'])
@login_required
@limiter.limit('30 per hour')
def cart_add_store(item_id):
    item = db.session.get(StoreItem, item_id) or abort(404)
    if not item.is_active or item.stock_status != 'available':
        abort(404)
    if not (item.price_iqd or parse_iqd_price(item.price)):
        flash('المنتج ما عنده سعر محدد حالياً.', 'error')
        return redirect(url_for('store_detail', item_id=item.id))
    try:
        quantity = min(99, max(1, int(request.form.get('quantity') or 1)))
    except (TypeError, ValueError):
        quantity = 1
    existing = CartItem.query.filter_by(user_id=current_user.id, item_type='store', store_item_id=item.id).first()
    if existing:
        existing.quantity = min(99, existing.quantity + quantity)
    else:
        db.session.add(CartItem(user_id=current_user.id, item_type='store', store_item_id=item.id, quantity=quantity))
    db.session.commit()
    flash('انضاف المنتج للسلة.', 'success')
    return redirect(url_for('store_detail', item_id=item.id))


@app.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
@login_required
def cart_remove(cart_item_id):
    row = CartItem.query.filter_by(id=cart_item_id, user_id=current_user.id).first_or_404()
    db.session.delete(row)
    db.session.commit()
    flash('انحذف العنصر من السلة.', 'success')
    return redirect(url_for('cart'))


@app.route('/cart/checkout', methods=['POST'])
@login_required
@limiter.limit('10 per hour')
def cart_checkout():
    rows = CartItem.query.filter_by(user_id=current_user.id).order_by(CartItem.id.asc()).all()
    entries = [(row, cart_entry(row)) for row in rows]
    if not entries or any(data is None for _, data in entries):
        flash('أحد العناصر لم يعد متاحاً أو تغير سعره. راجع السلة وحدّثها.', 'error')
        return redirect(url_for('cart'))
    if not terms_accepted():
        flash('وافق على الشروط وسياسة الطلب قبل إتمام الشراء.', 'error')
        return redirect(url_for('cart'))
    try:
        method_id = int(request.form.get('payment_method_id') or 0)
    except (TypeError, ValueError):
        method_id = 0
    method = db.session.get(PaymentMethod, method_id)
    if not is_supported_manual_payment(method):
        flash('اختر كي كارد أو زين كاش كطريقة دفع.', 'error')
        return redirect(url_for('cart'))
    contact = (request.form.get('contact') or '').strip()
    transaction_id = (request.form.get('transaction_id') or '').strip()
    refund_account = (request.form.get('refund_account') or '').strip()
    if not contact or not transaction_id or not refund_account:
        flash('أكمل رقم التواصل ورقم التحويل وحساب الاسترجاع.', 'error')
        return redirect(url_for('cart'))
    if len(contact) > 80 or len(transaction_id) > 250 or len(refund_account) > 250:
        flash('بعض البيانات أطول من الحد المسموح.', 'error')
        return redirect(url_for('cart'))
    for row, data in entries:
        if data['type'] == 'service' and is_account_recovery_service(db.session.get(Service, row.service_id)):
            flash('خدمة استعادة الحساب تُشترى مباشرة حتى ترفق صورة الحالة.', 'error')
            return redirect(url_for('cart'))
        line_details = (request.form.get(f'details_{row.id}') or '').strip()
        if len(line_details) > 2000:
            flash('ملاحظات أحد العناصر أطول من الحد المسموح.', 'error')
            return redirect(url_for('cart'))
        if data['type'] == 'service':
            line_url = (request.form.get(f'page_url_{row.id}') or '').strip()
            if not line_url or len(line_url) > 1000:
                flash('أضف رابط الحساب أو تفاصيل المشروع لكل خدمة.', 'error')
                return redirect(url_for('cart'))
    proof = save_payment_proof(request.files.get('payment_proof'))
    if not proof:
        flash('ارفع إثبات الدفع بصيغة صورة أو PDF.', 'error')
        return redirect(url_for('cart'))

    for row, data in entries:
        details = (request.form.get(f'details_{row.id}') or '').strip()
        if len(details) > 2000:
            flash('ملاحظات أحد العناصر أطول من الحد المسموح.', 'error')
            return redirect(url_for('cart'))
        if data['type'] == 'service':
            page_url = (request.form.get(f'page_url_{row.id}') or '').strip()
            if not page_url or len(page_url) > 1000:
                flash('أضف رابط الحساب أو تفاصيل المشروع لكل خدمة.', 'error')
                return redirect(url_for('cart'))
            if data['platform']:
                quantity_line = f"المطلوب: {data['package_quantity']:,} {data['package_unit']}\n" if data['package_quantity'] else ''
                group_line = f"نوع الخدمة: {data['package_group']}\n" if data['package_group'] else ''
                details = f"المنصة: {data['platform']}\n{group_line}{quantity_line}{details}".strip()
            db.session.add(ServiceOrder(
                user_id=current_user.id, service_id=row.service_id,
                payment_method_id=method.id, service_package_id=row.package_id,
                package_label=data['label'], amount=f"{data['line_total']:,} د.ع",
                page_url=page_url, details=details, contact=contact,
                refund_account=refund_account, transaction_id=transaction_id,
                proof_filename=proof, status='pending'
            ))
        else:
            quantity_note = f"الكمية: {data['quantity']}\n" if data['quantity'] > 1 else ''
            db.session.add(StoreOrder(
                user_id=current_user.id, store_item_id=row.store_item_id,
                payment_method_id=method.id, amount_iqd=data['line_total'],
                status='pending', contact=contact,
                details=(quantity_note + details).strip(), transaction_id=transaction_id,
                refund_account=refund_account, proof_filename=proof
            ))
        db.session.delete(row)
    db.session.commit()
    flash('وصلت طلباتك وإثبات الدفع، وهي الآن بانتظار مراجعة الإدارة.', 'success')
    return redirect(url_for('account'))


@app.route('/admin/store-orders')
@login_required
def admin_store_orders():
    if not admin_only():
        abort(403)
    return render_template('admin_store_orders.html', orders=StoreOrder.query.order_by(StoreOrder.id.desc()).all())


@app.route('/admin/store-order-proof/<int:order_id>')
@login_required
def admin_store_order_proof(order_id):
    if not admin_only():
        abort(403)
    order = db.session.get(StoreOrder, order_id) or abort(404)
    if not order.proof_filename:
        abort(404)
    return send_from_directory(
        app.config['PAYMENT_PROOF_FOLDER'],
        os.path.basename(order.proof_filename),
        conditional=True
    )


@app.route('/admin/store-order/<int:order_id>/<action>', methods=['POST'])
@login_required
def admin_store_order_action(order_id, action):
    if not admin_only():
        abort(403)
    order = db.session.get(StoreOrder, order_id) or abort(404)
    transitions = {
        'pending': {'approve': 'approved', 'reject': 'rejected'},
        'approved': {'complete': 'completed', 'reject': 'rejected'},
    }
    next_status = transitions.get(order.status, {}).get(action)
    if not next_status:
        flash('هذا الانتقال غير مسموح أو الطلب تمت معالجته مسبقاً.', 'error')
        return redirect(url_for('admin_store_orders'))
    note = (request.form.get('admin_note') or '').strip()[:250]
    if action == 'reject' and order.payment_method_id is None:
        existing_refund = WalletTransaction.query.filter_by(
            user_id=order.user_id, transaction_type='refund',
            reference_type='store_order_refund', reference_id=order.id
        ).first()
        if not existing_refund:
            db.session.add(WalletTransaction(user_id=order.user_id, transaction_type='refund',
                amount_iqd=order.amount_iqd, reference_type='store_order_refund', reference_id=order.id,
                note=f'استرجاع مبلغ طلب متجر #{order.id}'))
    order.status = next_status
    order.admin_note = note
    db.session.commit()
    flash('تم تحديث طلب المتجر.', 'success')
    return redirect(url_for('admin_store_orders'))


@app.route('/admin/services')
@login_required
def admin_services():
    if not admin_only():
        abort(403)
    return render_template('admin_services.html',
                           services=Service.query.order_by(Service.position.asc(), Service.id.asc()).all(),
                           social_package_group_choices=SOCIAL_PACKAGE_GROUP_CHOICES)


@app.route('/admin/service/new', methods=['POST'])
@login_required
def admin_service_new():
    if not admin_only():
        abort(403)
    title=(request.form.get('title') or '').strip()
    try:
        position = max(1, int(request.form.get('position') or 1))
    except ValueError:
        position = 1
    if not title:
        flash('اسم الخدمة مطلوب.', 'error')
        return redirect(url_for('admin_services'))

    package_labels = request.form.getlist('package_label')
    package_quantities = request.form.getlist('package_quantity')
    package_prices = request.form.getlist('package_price_iqd')
    package_descriptions = request.form.getlist('package_description')
    package_group_keys = request.form.getlist('package_group_key')
    packages = []
    package_rows = max(len(package_labels), len(package_quantities), len(package_prices), len(package_descriptions), len(package_group_keys))
    for index in range(package_rows):
        label = package_labels[index].strip() if index < len(package_labels) else ''
        raw_quantity = package_quantities[index].strip().replace(',', '') if index < len(package_quantities) else ''
        raw_price = package_prices[index].strip().replace(',', '') if index < len(package_prices) else ''
        description = package_descriptions[index].strip() if index < len(package_descriptions) else ''
        group_key = package_group_keys[index].strip() if index < len(package_group_keys) else ''
        if not label and not raw_quantity and not raw_price and not description:
            continue
        if not label or not raw_quantity.isdigit() or int(raw_quantity) < 1 or not raw_price.isdigit() or int(raw_price) < 1:
            flash('أكمل اسم وكمية وسعر كل باقة، أو اترك حقولها فارغة.', 'error')
            return redirect(url_for('admin_services'))
        if group_key and group_key not in SOCIAL_PACKAGE_GROUPS:
            flash('مجموعة الباقة غير صحيحة.', 'error')
            return redirect(url_for('admin_services'))
        packages.append((label[:120], int(raw_quantity), int(raw_price), description[:2000], group_key))

    service = Service(
        title=title[:160],
        category=((request.form.get('category') or 'خدمات رقمية').strip())[:80],
        short_description=((request.form.get('short_description') or '').strip())[:280],
        description=(request.form.get('description') or '').strip(),
        price=((request.form.get('price') or 'حسب الطلب').strip())[:60],
        price_iqd=parse_iqd_price(request.form.get('price_iqd')),
        position=position,
        is_active=bool(request.form.get('is_active'))
    )
    db.session.add(service)
    db.session.flush()
    for package_position, (label, quantity, price_iqd, description, group_key) in enumerate(packages, 1):
        db.session.add(ServicePackage(
            service_id=service.id,
            label=label,
            quantity=quantity,
            price_iqd=price_iqd,
            description=description,
            group_key=group_key,
            position=package_position,
            is_active=True
        ))
    db.session.commit()
    flash('تمت إضافة الخدمة وباقاتها.' if packages else 'تمت إضافة الخدمة.', 'success')
    return redirect(url_for('admin_services'))


@app.route('/admin/service/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_service_edit(item_id):
    if not admin_only():
        abort(403)
    item = db.session.get(Service, item_id) or abort(404)

    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        if not title:
            flash('اسم الخدمة مطلوب.', 'error')
            return redirect(url_for('admin_service_edit', item_id=item.id))
        try:
            position = max(1, int(request.form.get('position') or 1))
        except ValueError:
            position = 1

        item.title = title[:160]
        item.category = ((request.form.get('category') or 'خدمات رقمية').strip())[:80]
        item.short_description = ((request.form.get('short_description') or '').strip())[:280]
        item.description = (request.form.get('description') or '').strip()
        item.price = ((request.form.get('price') or 'حسب الطلب').strip())[:60]
        item.price_iqd = parse_iqd_price(request.form.get('price_iqd'))
        item.position = position
        item.is_active = bool(request.form.get('is_active'))
        db.session.commit()
        flash('تم تحديث الخدمة.', 'success')
        return redirect(url_for('admin_services'))

    return render_template('admin_service_edit.html', service=item,
                           social_package_group_choices=SOCIAL_PACKAGE_GROUP_CHOICES)


@app.route('/admin/service/<int:item_id>/package/new', methods=['POST'])
@login_required
def admin_service_package_new(item_id):
    if not admin_only():
        abort(403)
    item = db.session.get(Service, item_id) or abort(404)
    label = (request.form.get('label') or '').strip()
    try:
        quantity = max(1, int(request.form.get('quantity') or 0))
        price_iqd = max(0, int(request.form.get('price_iqd') or 0))
        position = max(1, int(request.form.get('position') or 1))
    except ValueError:
        flash('العدد والسعر يجب أن يكونا أرقاماً.', 'error')
        return redirect(url_for('admin_service_edit', item_id=item.id))
    if not label:
        label = f'{quantity:,} متابع'
    group_key = (request.form.get('group_key') or '').strip()
    if group_key and group_key not in SOCIAL_PACKAGE_GROUPS:
        flash('مجموعة الباقة غير صحيحة.', 'error')
        return redirect(url_for('admin_service_edit', item_id=item.id))
    db.session.add(ServicePackage(service_id=item.id, label=label[:120], quantity=quantity, price_iqd=price_iqd, position=position, is_active=True, group_key=group_key))
    db.session.commit()
    flash('تمت إضافة الباقة.', 'success')
    return redirect(url_for('admin_service_edit', item_id=item.id))


@app.route('/admin/service/package/<int:package_id>/edit', methods=['POST'])
@login_required
def admin_service_package_edit(package_id):
    if not admin_only():
        abort(403)
    package = db.session.get(ServicePackage, package_id) or abort(404)
    try:
        quantity = max(1, int(request.form.get('quantity') or package.quantity))
        price_iqd = max(0, int(request.form.get('price_iqd') or package.price_iqd))
        position = max(1, int(request.form.get('position') or package.position))
    except ValueError:
        flash('العدد والسعر يجب أن يكونا أرقاماً.', 'error')
        return redirect(url_for('admin_service_edit', item_id=package.service_id))
    package.label = ((request.form.get('label') or f'{quantity:,} متابع').strip())[:120]
    package.description = (request.form.get('description') or '').strip()[:2000]
    group_key = (request.form.get('group_key') or '').strip()
    if group_key and group_key not in SOCIAL_PACKAGE_GROUPS:
        flash('مجموعة الباقة غير صحيحة.', 'error')
        return redirect(url_for('admin_service_edit', item_id=package.service_id))
    package.group_key = group_key
    package.quantity = quantity
    package.price_iqd = price_iqd
    package.position = position
    package.is_active = bool(request.form.get('is_active'))
    db.session.commit()
    flash('تم تحديث الباقة.', 'success')
    return redirect(url_for('admin_service_edit', item_id=package.service_id))


@app.route('/admin/service/<int:item_id>/toggle', methods=['POST'])
@login_required
def admin_service_toggle(item_id):
    if not admin_only():
        abort(403)
    item=db.session.get(Service,item_id) or abort(404)
    item.is_active=not item.is_active
    db.session.commit()
    return redirect(url_for('admin_services'))


@app.route('/admin/store')
@login_required
def admin_store():
    if not admin_only():
        abort(403)
    return render_template('admin_store.html', items=StoreItem.query.order_by(StoreItem.position.asc(), StoreItem.id.asc()).all())


@app.route('/admin/store/new', methods=['POST'])
@login_required
def admin_store_new():
    if not admin_only():
        abort(403)
    title=(request.form.get('title') or '').strip()
    if not title:
        flash('اسم العرض مطلوب.', 'error')
        return redirect(url_for('admin_store'))
    try:
        store_position = max(1, int(request.form.get('position') or 1))
    except ValueError:
        store_position = 1
    db.session.add(StoreItem(
        title=title,
        category=(request.form.get('category') or 'منتج رقمي').strip(),
        short_description=(request.form.get('short_description') or '').strip(),
        description=(request.form.get('description') or '').strip(),
        price=(request.form.get('price') or 'حسب العرض').strip(),
        price_iqd=parse_iqd_price(request.form.get('price_iqd')),
        stock_status=(request.form.get('stock_status') or 'available').strip(),
        position=store_position,
        is_active=bool(request.form.get('is_active'))
    ))
    db.session.commit()
    flash('تمت إضافة العرض للمتجر.', 'success')
    return redirect(url_for('admin_store'))


@app.route('/admin/store/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_store_edit(item_id):
    if not admin_only():
        abort(403)
    item = db.session.get(StoreItem, item_id) or abort(404)
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        if not title:
            flash('اسم العرض مطلوب.', 'error')
            return redirect(url_for('admin_store_edit', item_id=item.id))
        try:
            position = max(1, int(request.form.get('position') or 1))
        except ValueError:
            position = 1
        stock_status = (request.form.get('stock_status') or 'available').strip()
        if stock_status not in {'available', 'sold'}:
            stock_status = 'available'
        item.title = title
        item.category = (request.form.get('category') or 'منتج رقمي').strip()
        item.short_description = (request.form.get('short_description') or '').strip()[:280]
        item.description = (request.form.get('description') or '').strip()
        item.price = (request.form.get('price') or 'حسب العرض').strip()[:60]
        item.price_iqd = parse_iqd_price(request.form.get('price_iqd'))
        item.stock_status = stock_status
        item.position = position
        item.is_active = bool(request.form.get('is_active'))
        db.session.commit()
        flash('تم تحديث العرض.', 'success')
        return redirect(url_for('admin_store'))
    return render_template('admin_store_edit.html', item=item)


@app.route('/admin/store/<int:item_id>/toggle', methods=['POST'])
@login_required
def admin_store_toggle(item_id):
    if not admin_only():
        abort(403)
    item=db.session.get(StoreItem,item_id) or abort(404)
    item.is_active=not item.is_active
    db.session.commit()
    return redirect(url_for('admin_store'))


# =========================
# Account validation helpers
# =========================

USERNAME_RE = re.compile(r'^[A-Za-z0-9._]{3,30}$')
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def normalize_username(value):
    return (value or '').strip().lower()


def normalize_email(value):
    return (value or '').strip().lower()


def normalize_iraqi_phone(value):
    value = re.sub(r'[\s\-\(\)]', '', (value or '').strip())

    if value.startswith('00964'):
        value = '+' + value[2:]
    elif value.startswith('964'):
        value = '+' + value
    elif value.startswith('07') and len(value) == 11:
        value = '+964' + value[1:]

    if re.fullmatch(r'\+9647\d{9}', value):
        return value

    return None


def valid_username(value):
    return bool(USERNAME_RE.fullmatch(value or ''))


def valid_email(value):
    return bool(
        value
        and len(value) <= 254
        and EMAIL_RE.fullmatch(value)
    )


def valid_password(value):
    return (
        len(value or '') >= 8
        and bool(re.search(r'[A-Za-z]', value))
        and bool(re.search(r'\d', value))
    )


# =========================
# Registration verification
# =========================

REGISTER_OTP_MINUTES = 10
REGISTER_OTP_MAX_ATTEMPTS = 5
# Phone signup verification remains paused until WhatsApp delivery is integrated.
PHONE_REGISTRATION_ENABLED = False


def registration_contact_exists(method, contact):
    if method == 'email':
        return (
            User.query.filter(db.func.lower(User.email) == contact).first()
            or User.query.filter(db.func.lower(User.email_or_phone) == contact).first()
        ) is not None

    return (
        User.query.filter_by(phone=contact).first()
        or User.query.filter_by(email_or_phone=contact).first()
    ) is not None


def deliver_registration_email(contact, code):
    if not os.environ.get('RAILWAY_ENVIRONMENT'):
        flash(f'LOCAL TEST OTP: {code}', 'message')
        return True

    api_key = (os.environ.get('RESEND_API_KEY') or '').strip()
    from_email = (
        os.environ.get('RESEND_FROM_EMAIL')
        or 'Rabbit Security <security@rabbitrq.com>'
    ).strip()

    if not api_key:
        app.logger.error('Registration email could not be sent: missing Resend config.')
        return False

    resend.api_key = api_key

    params = {
        'from': from_email,
        'to': [contact],
        'subject': 'رمز تأكيد حسابك - RABBIT',
        'html': (
            '<div dir="rtl" style="font-family:Arial,sans-serif;line-height:1.8">'
            '<h2>RABBIT</h2>'
            '<p>رمز تأكيد إنشاء حسابك هو:</p>'
            f'<p style="font-size:30px;font-weight:700;letter-spacing:6px">{code}</p>'
            f'<p>ينتهي هذا الرمز خلال {REGISTER_OTP_MINUTES} دقائق.</p>'
            '<p>إذا لم تطلب إنشاء حساب، تجاهل هذه الرسالة.</p>'
            '</div>'
        ),
        'text': (
            f'RABBIT\n\nرمز تأكيد إنشاء الحساب: {code}\n'
            f'ينتهي الرمز خلال {REGISTER_OTP_MINUTES} دقائق.'
        )
    }

    try:
        resend.Emails.send(params)
        return True
    except Exception as exc:
        app.logger.error(
            'Resend registration delivery failed: %s',
            type(exc).__name__
        )
        return False


def clear_registration_session():
    for key in (
        'reg_method',
        'reg_contact',
        'reg_code_hash',
        'reg_expires_at',
        'reg_attempts',
        'reg_verified'
    ):
        session.pop(key, None)


def find_user_by_login_identifier(identifier):
    raw = (identifier or '').strip()
    username = normalize_username(raw)
    email = normalize_email(raw)
    phone = normalize_iraqi_phone(raw)

    user = User.query.filter(
        db.func.lower(User.username) == username
    ).first()
    if user:
        return user

    if valid_email(email):
        user = User.query.filter(
            db.func.lower(User.email) == email
        ).first()
        if user:
            return user

        user = User.query.filter(
            db.func.lower(User.email_or_phone) == email
        ).first()
        if user:
            return user

    if phone:
        user = User.query.filter_by(phone=phone).first()
        if user:
            return user

        user = User.query.filter_by(email_or_phone=phone).first()
        if user:
            return user

    return None


# =========================
# Password recovery
# =========================

RESET_OTP_MINUTES = 10
RESET_OTP_MAX_ATTEMPTS = 5


def find_user_by_recovery_identifier(identifier):
    raw = (identifier or '').strip()
    email = normalize_email(raw)
    phone = normalize_iraqi_phone(raw)

    if valid_email(email):
        user = User.query.filter(
            db.func.lower(User.email) == email
        ).first()
        if user:
            return user

        # Backward compatibility for old accounts.
        return User.query.filter(
            db.func.lower(User.email_or_phone) == email
        ).first()

    if phone:
        user = User.query.filter_by(
            phone=phone
        ).first()
        if user:
            return user

        return User.query.filter_by(
            email_or_phone=phone
        ).first()

    return None


def deliver_password_reset_code(user, code):
    """
    Deliver a password-reset OTP.

    Local development keeps the existing flash-based test flow.
    On Railway, delivery uses Resend's official Python SDK and environment
    variables only. The API key and OTP are never written to application logs.
    """
    if not os.environ.get('RAILWAY_ENVIRONMENT'):
        flash(
            f'LOCAL TEST OTP: {code}',
            'message'
        )
        return True

    api_key = (os.environ.get('RESEND_API_KEY') or '').strip()
    from_email = (
        os.environ.get('RESEND_FROM_EMAIL')
        or 'Rabbit Security <security@rabbitrq.com>'
    ).strip()

    recipient = normalize_email(user.email)

    # Backward compatibility for an old account whose email still lives only
    # in the legacy contact field.
    if not valid_email(recipient):
        legacy_email = normalize_email(user.email_or_phone)
        recipient = legacy_email if valid_email(legacy_email) else ''

    if not api_key or not recipient:
        app.logger.error(
            'Password reset email could not be sent: missing Resend config '
            'or recipient email for user_id=%s.',
            user.id
        )
        return False

    resend.api_key = api_key

    params = {
        'from': from_email,
        'to': [recipient],
        'subject': 'رمز استرجاع كلمة المرور - RABBIT',
        'html': (
            '<div dir="rtl" style="font-family:Arial,sans-serif;line-height:1.8">'
            '<h2>RABBIT</h2>'
            '<p>رمز التحقق لاسترجاع كلمة المرور هو:</p>'
            f'<p style="font-size:30px;font-weight:700;letter-spacing:6px">{code}</p>'
            f'<p>ينتهي هذا الرمز خلال {RESET_OTP_MINUTES} دقائق.</p>'
            '<p>إذا لم تطلب تغيير كلمة المرور، تجاهل هذه الرسالة.</p>'
            '</div>'
        ),
        'text': (
            f'RABBIT\n\nرمز التحقق لاسترجاع كلمة المرور: {code}\n'
            f'ينتهي الرمز خلال {RESET_OTP_MINUTES} دقائق.\n'
            'إذا لم تطلب تغيير كلمة المرور، تجاهل هذه الرسالة.'
        )
    }

    try:
        resend.Emails.send(params)
        return True
    except Exception as exc:
        # Never log the OTP, API key, recipient address, or provider body.
        app.logger.error(
            'Resend password reset delivery failed for user_id=%s: %s',
            user.id,
            type(exc).__name__
        )
        return False


@app.route(
    '/forgot-password',
    methods=['GET', 'POST']
)
@limiter.limit("5 per hour", methods=["POST"])
def forgot_password():

    if request.method == 'POST':

        identifier = (
            request.form.get('identifier')
            or ''
        ).strip()

        user = find_user_by_recovery_identifier(
            identifier
        )

        # إذا الإيميل أو الرقم غير موجود، نرجع لنفس الصفحة
        # برسالة خطأ حمراء، ولا ننتقل إلى صفحة رمز التحقق.
        if not user:
            flash(
                'هذا البريد الإلكتروني أو رقم الهاتف غير مرتبط بأي حساب.',
                'error'
            )
            return redirect(
                url_for('forgot_password')
            )

        # إلغاء أي رموز استرجاع قديمة غير مستخدمة.
        PasswordResetOTP.query.filter_by(
            user_id=user.id,
            used=False
        ).update(
            {'used': True}
        )

        # إنشاء رمز تحقق من 6 أرقام.
        code = f'{secrets.randbelow(1000000):06d}'

        reset = PasswordResetOTP(
            user_id=user.id,
            code_hash=generate_password_hash(code),
            expires_at=(
                datetime.utcnow()
                + timedelta(minutes=RESET_OTP_MINUTES)
            )
        )

        db.session.add(reset)
        db.session.commit()

        # إرسال الرمز إلى وسيلة التواصل المرتبطة بالحساب.
        sent = deliver_password_reset_code(
            user,
            code
        )

        # إذا فشل الإرسال، لا ننقل المستخدم إلى صفحة OTP.
        if not sent:
            PasswordResetOTP.query.filter_by(
                id=reset.id
            ).update(
                {'used': True}
            )
            db.session.commit()

            flash(
                'تعذر إرسال رمز التحقق حالياً. حاول مرة أخرى بعد قليل.',
                'error'
            )
            return redirect(
                url_for('forgot_password')
            )

        session['reset_identifier'] = identifier

        return redirect(
            url_for('verify_reset_code')
        )

    return render_template(
        'forgot_password.html'
    )


@app.route(
    '/verify-reset-code',
    methods=['GET', 'POST']
)
@limiter.limit("10 per minute", methods=["POST"])
def verify_reset_code():

    identifier = session.get(
        'reset_identifier'
    )

    if not identifier:
        return redirect(
            url_for('forgot_password')
        )

    if request.method == 'POST':

        code = (
            request.form.get('code')
            or ''
        ).strip()

        user = find_user_by_recovery_identifier(
            identifier
        )

        reset = None

        if user:
            reset = PasswordResetOTP.query.filter_by(
                user_id=user.id,
                used=False
            ).order_by(
                PasswordResetOTP.id.desc()
            ).first()

        valid = (
            reset
            and reset.expires_at >= datetime.utcnow()
            and reset.attempts < RESET_OTP_MAX_ATTEMPTS
            and re.fullmatch(r'\d{6}', code)
            and check_password_hash(
                reset.code_hash,
                code
            )
        )

        if not valid:

            if reset:
                reset.attempts += 1

                if (
                    reset.attempts
                    >= RESET_OTP_MAX_ATTEMPTS
                ):
                    reset.used = True

                db.session.commit()

            flash(
                'رمز التحقق غير صحيح أو منتهي الصلاحية.',
                'error'
            )

            return redirect(
                url_for('verify_reset_code')
            )

        reset.used = True
        db.session.commit()

        session.pop(
            'reset_identifier',
            None
        )

        session['password_reset_user_id'] = user.id
        session['password_reset_authorized_at'] = (
            datetime.utcnow().isoformat()
        )

        return redirect(
            url_for('reset_password')
        )

    return render_template(
        'verify_reset_code.html'
    )


@app.route(
    '/reset-password',
    methods=['GET', 'POST']
)
@limiter.limit("10 per minute", methods=["POST"])
def reset_password():

    user_id = session.get(
        'password_reset_user_id'
    )

    authorized_at_raw = session.get(
        'password_reset_authorized_at'
    )

    if not user_id or not authorized_at_raw:
        return redirect(
            url_for('forgot_password')
        )

    try:
        authorized_at = datetime.fromisoformat(
            authorized_at_raw
        )
    except ValueError:
        session.pop(
            'password_reset_user_id',
            None
        )
        session.pop(
            'password_reset_authorized_at',
            None
        )
        return redirect(
            url_for('forgot_password')
        )

    if (
        datetime.utcnow() - authorized_at
        > timedelta(minutes=10)
    ):
        session.pop(
            'password_reset_user_id',
            None
        )
        session.pop(
            'password_reset_authorized_at',
            None
        )

        flash(
            'انتهت صلاحية جلسة الاسترجاع. اطلب رمزاً جديداً.',
            'error'
        )

        return redirect(
            url_for('forgot_password')
        )

    user = db.session.get(
        User,
        user_id
    )

    if not user:
        abort(404)

    if request.method == 'POST':

        password = (
            request.form.get('password')
            or ''
        )

        confirm_password = (
            request.form.get('confirm_password')
            or ''
        )

        if password != confirm_password:
            flash(
                'كلمتا المرور غير متطابقتين.',
                'error'
            )
            return redirect(
                url_for('reset_password')
            )

        if not valid_password(password):
            flash(
                'كلمة المرور يجب أن تكون 8 خانات على الأقل وتحتوي حرفاً إنجليزياً ورقماً.',
                'error'
            )
            return redirect(
                url_for('reset_password')
            )

        user.password = generate_password_hash(
            password
        )

        db.session.commit()

        session.pop(
            'password_reset_user_id',
            None
        )
        session.pop(
            'password_reset_authorized_at',
            None
        )

        flash(
            'تم تغيير كلمة المرور. سجل دخولك بكلمة المرور الجديدة.',
            'success'
        )

        return redirect(
            url_for('auth_page')
        )

    return render_template(
        'reset_password.html'
    )


# =========================
# Login / Register
# =========================

@app.route(
    '/auth',
    methods=['GET', 'POST']
)
@limiter.limit("10 per minute", methods=["POST"])
def auth_page():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    mode = request.args.get('mode', 'login')
    if mode not in ('login', 'register'):
        mode = 'login'

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()

        if action == 'login':
            identifier = (request.form.get('identifier') or '').strip()
            password = request.form.get('password') or ''

            if not identifier or not password:
                flash('أدخل اسم المستخدم أو الإيميل أو رقم الهاتف وكلمة المرور.', 'error')
                return redirect(url_for('auth_page'))

            user = find_user_by_login_identifier(identifier)

            if user and check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))

            flash('بيانات تسجيل الدخول غير صحيحة.', 'error')
            return redirect(url_for('auth_page'))

        if action == 'register_start':
            method = (request.form.get('contact_method') or '').strip()
            raw_contact = (request.form.get('contact') or '').strip()

            if method == 'phone' and not PHONE_REGISTRATION_ENABLED:
                flash('إنشاء الحساب متاح حالياً عبر البريد الإلكتروني فقط.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            if method == 'email':
                contact = normalize_email(raw_contact)
                if not valid_email(contact):
                    flash('اكتب بريداً إلكترونياً صحيحاً.', 'error')
                    return redirect(url_for('auth_page', mode='register'))

            elif method == 'phone':
                contact = normalize_iraqi_phone(raw_contact)
                if not contact:
                    flash('اكتب رقم موبايل عراقي صحيح، مثال: 07XXXXXXXXX.', 'error')
                    return redirect(url_for('auth_page', mode='register'))

                # SMS/WhatsApp provider is intentionally not faked.
                flash('تأكيد رقم الهاتف سيُفعّل بعد ربط مزود الرسائل. استخدم البريد الإلكتروني حالياً.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            else:
                flash('اختر البريد الإلكتروني أو رقم الهاتف.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            if registration_contact_exists(method, contact):
                flash('هذه وسيلة التواصل مرتبطة بحساب مسبقاً.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            code = f'{secrets.randbelow(1000000):06d}'

            clear_registration_session()
            session['reg_method'] = method
            session['reg_contact'] = contact
            session['reg_code_hash'] = generate_password_hash(code)
            session['reg_expires_at'] = (
                datetime.utcnow() + timedelta(minutes=REGISTER_OTP_MINUTES)
            ).isoformat()
            session['reg_attempts'] = 0
            session['reg_verified'] = False

            if not deliver_registration_email(contact, code):
                clear_registration_session()
                flash('تعذر إرسال رمز التحقق حالياً. حاول مرة أخرى بعد قليل.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            flash('أرسلنا رمز تحقق من 6 أرقام إلى بريدك.', 'success')
            return redirect(url_for('auth_page', mode='register'))

        if action == 'register_verify':
            contact = session.get('reg_contact')
            code_hash = session.get('reg_code_hash')
            expires_raw = session.get('reg_expires_at')
            attempts = int(session.get('reg_attempts', 0))
            code = re.sub(r'\D', '', request.form.get('code') or '')

            if not contact or not code_hash or not expires_raw:
                clear_registration_session()
                flash('ابدأ إنشاء الحساب من جديد.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            try:
                expires_at = datetime.fromisoformat(expires_raw)
            except ValueError:
                clear_registration_session()
                flash('انتهت جلسة التحقق. اطلب رمزاً جديداً.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            valid = (
                datetime.utcnow() <= expires_at
                and attempts < REGISTER_OTP_MAX_ATTEMPTS
                and re.fullmatch(r'\d{6}', code)
                and check_password_hash(code_hash, code)
            )

            if not valid:
                session['reg_attempts'] = attempts + 1
                if session['reg_attempts'] >= REGISTER_OTP_MAX_ATTEMPTS:
                    clear_registration_session()
                    flash('انتهت محاولات التحقق. اطلب رمزاً جديداً.', 'error')
                else:
                    flash('رمز التحقق غير صحيح أو منتهي الصلاحية.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            session['reg_verified'] = True
            session.pop('reg_code_hash', None)
            session.pop('reg_expires_at', None)
            session.pop('reg_attempts', None)

            flash('تم تأكيد البريد. أكمل بيانات حسابك.', 'success')
            return redirect(url_for('auth_page', mode='register'))

        if action == 'register_complete':
            if not session.get('reg_verified'):
                flash('يجب تأكيد وسيلة التواصل أولاً.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            method = session.get('reg_method')
            contact = session.get('reg_contact')
            username = normalize_username(request.form.get('username'))
            password = request.form.get('password') or ''

            if method != 'email' or not contact:
                clear_registration_session()
                flash('انتهت جلسة التسجيل. ابدأ من جديد.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            if not valid_username(username):
                flash(
                    'اسم المستخدم يجب أن يكون من 3 إلى 30 خانة وبالأحرف الإنجليزية والأرقام و . و _ فقط.',
                    'error'
                )
                return redirect(url_for('auth_page', mode='register'))

            if not valid_password(password):
                flash(
                    'كلمة المرور يجب أن تكون 8 خانات على الأقل وتحتوي حرفاً إنجليزياً ورقماً.',
                    'error'
                )
                return redirect(url_for('auth_page', mode='register'))

            if User.query.filter(db.func.lower(User.username) == username).first():
                flash('اسم المستخدم مستخدم مسبقاً.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            if registration_contact_exists(method, contact):
                clear_registration_session()
                flash('وسيلة التواصل أصبحت مرتبطة بحساب آخر. ابدأ من جديد.', 'error')
                return redirect(url_for('auth_page', mode='register'))

            user = User(
                username=username,
                email=contact if method == 'email' else None,
                phone=contact if method == 'phone' else None,
                email_or_phone=contact,
                password=generate_password_hash(password),
                email_verified=(method == 'email'),
                phone_verified=(method == 'phone'),
                is_admin=False
            )

            db.session.add(user)
            db.session.commit()
            clear_registration_session()
            login_user(user)

            flash('تم إنشاء الحساب وتأكيده بنجاح.', 'success')
            return redirect(url_for('home'))

        if action == 'register_restart':
            clear_registration_session()
            return redirect(url_for('auth_page', mode='register'))

        flash('حدث خطأ في الطلب، حاول مرة أخرى.', 'error')
        return redirect(url_for('auth_page', mode=mode))

    reg_stage = 'contact'
    if session.get('reg_contact') and not session.get('reg_verified'):
        reg_stage = 'verify'
    elif session.get('reg_contact') and session.get('reg_verified'):
        reg_stage = 'complete'

    return render_template(
        'login.html',
        auth_mode=mode,
        reg_stage=reg_stage,
        reg_method=session.get('reg_method'),
        reg_contact=session.get('reg_contact'),
        phone_registration_enabled=PHONE_REGISTRATION_ENABLED
    )


# =========================
# Courses
# =========================

@app.route('/courses')
def courses():
    # The public catalog stays visible as a coming-soon page until launch.
    return render_template('courses_coming_soon.html')


@app.route(
    '/course/<int:course_id>'
)
def course_detail(course_id):

    c = db.session.get(
        Course,
        course_id
    )

    if not c:
        abort(404)

    if (
        not c.is_published
        and not admin_only()
    ):
        abort(404)

    has_course_access = False
    enrollment = None

    if current_user.is_authenticated:

        if current_user.is_admin:

            has_course_access = True

        else:

            enrollment = Enrollment.query.filter_by(
                user_id=current_user.id,
                course_id=c.id
            ).first()

            if (
                enrollment
                and enrollment.status == 'approved'
            ):
                has_course_access = True

    completed_lesson_ids = set()
    if current_user.is_authenticated and has_course_access:
        completed_lesson_ids = {
            row.lesson_id for row in LessonProgress.query.filter_by(
                user_id=current_user.id, completed=True
            ).filter(LessonProgress.lesson_id.in_([l.id for l in c.lessons] or [-1])).all()
        }

    return render_template(
        'course_detail.html',
        course=c,
        has_course_access=has_course_access,
        enrollment=enrollment,
        completed_lesson_ids=completed_lesson_ids
    )


@app.route('/learn')
@login_required
def learning_hub():
    enrollments = Enrollment.query.filter_by(
        user_id=current_user.id, status='approved'
    ).order_by(Enrollment.id.desc()).all()
    cards = []
    for enrollment in enrollments:
        course = enrollment.course
        lessons = list(course.lessons)
        lesson_ids = [l.id for l in lessons]
        completed_ids = set()
        if lesson_ids:
            completed_ids = {
                row.lesson_id for row in LessonProgress.query.filter(
                    LessonProgress.user_id == current_user.id,
                    LessonProgress.completed.is_(True),
                    LessonProgress.lesson_id.in_(lesson_ids)
                ).all()
            }
        next_lesson = next((l for l in lessons if l.id not in completed_ids), lessons[-1] if lessons else None)
        total = len(lessons)
        completed = len(completed_ids)
        percent = int((completed / total) * 100) if total else 0
        cards.append({'course': course, 'total': total, 'completed': completed,
                      'percent': percent, 'next_lesson': next_lesson})
    return render_template('learning_hub.html', cards=cards)


@app.route('/lesson/<int:lesson_id>/complete', methods=['POST'])
@login_required
def lesson_complete(lesson_id):
    lesson = db.session.get(Lesson, lesson_id) or abort(404)
    enrollment = Enrollment.query.filter_by(
        user_id=current_user.id, course_id=lesson.course_id, status='approved'
    ).first()
    if not enrollment and not current_user.is_admin:
        abort(403)
    progress = LessonProgress.query.filter_by(user_id=current_user.id, lesson_id=lesson.id).first()
    if not progress:
        progress = LessonProgress(user_id=current_user.id, lesson_id=lesson.id)
        db.session.add(progress)
    if not progress.completed:
        progress.completed = True
        progress.completed_at = datetime.utcnow()
        progress.updated_at = datetime.utcnow()
        db.session.commit()
    return ('', 204)


@app.route('/lesson/<int:lesson_id>/progress', methods=['POST'])
@login_required
def lesson_progress_toggle(lesson_id):
    lesson = db.session.get(Lesson, lesson_id) or abort(404)
    enrollment = Enrollment.query.filter_by(
        user_id=current_user.id, course_id=lesson.course_id, status='approved'
    ).first()
    if not enrollment and not current_user.is_admin:
        abort(403)
    progress = LessonProgress.query.filter_by(user_id=current_user.id, lesson_id=lesson.id).first()
    if not progress:
        progress = LessonProgress(user_id=current_user.id, lesson_id=lesson.id)
        db.session.add(progress)
    progress.completed = not progress.completed
    progress.completed_at = datetime.utcnow() if progress.completed else None
    progress.updated_at = datetime.utcnow()
    db.session.commit()
    return redirect(url_for('course_detail', course_id=lesson.course_id, _anchor=f'lesson-{lesson.id}'))


# =========================
# Course Enrollment
# =========================

@app.route(
    '/course/<int:course_id>/enroll',
    methods=['POST']
)
@login_required
def request_course_enrollment(course_id):
    c = db.session.get(Course, course_id) or abort(404)

    enrollment = Enrollment.query.filter_by(
        user_id=current_user.id,
        course_id=c.id
    ).first()

    if enrollment and enrollment.status == 'approved':
        flash('هذا الكورس مفعّل عندك بالفعل.', 'success')
        return redirect(url_for('course_detail', course_id=c.id))

    if not enrollment:
        enrollment = Enrollment(
            user_id=current_user.id,
            course_id=c.id,
            status='pending'
        )
        db.session.add(enrollment)
        db.session.commit()

    return redirect(url_for('course_payment', course_id=c.id))


@app.route('/course/<int:course_id>/buy-wallet', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def course_buy_wallet(course_id):
    c = db.session.get(Course, course_id) or abort(404)
    if not c.is_published and not admin_only():
        abort(404)
    amount_iqd = c.price_iqd or parse_iqd_price(c.price)
    if not amount_iqd:
        flash('هذا الكورس لا يملك سعراً بالدينار للدفع من الرصيد حالياً.', 'error')
        return redirect(url_for('course_detail', course_id=c.id))
    enrollment = Enrollment.query.filter_by(user_id=current_user.id, course_id=c.id).first()
    if enrollment and enrollment.status == 'approved':
        flash('هذا الكورس مفعّل عندك بالفعل.', 'success')
        return redirect(url_for('course_detail', course_id=c.id))
    db.session.execute(sql_text('SELECT id FROM "user" WHERE id = :uid FOR UPDATE'), {'uid': current_user.id})
    if wallet_balance_iqd(current_user.id) < amount_iqd:
        db.session.rollback()
        flash('رصيدك غير كافي. أضف رصيداً ثم أعد المحاولة.', 'error')
        return redirect(url_for('course_detail', course_id=c.id))
    if not enrollment:
        enrollment = Enrollment(user_id=current_user.id, course_id=c.id, status='approved')
        db.session.add(enrollment)
        db.session.flush()
    else:
        enrollment.status = 'approved'
    db.session.add(WalletTransaction(user_id=current_user.id, transaction_type='purchase',
        amount_iqd=-amount_iqd, reference_type='course', reference_id=c.id,
        note=f'شراء كورس: {c.title}'[:250]))
    db.session.commit()
    flash('تم شراء الكورس وتفعيله. دخلناك مباشرة إلى منطقة الدراسة.', 'success')
    return redirect(url_for('learning_hub'))


# =========================
# Customer Course Payment
# =========================
@app.route(
    '/course/<int:course_id>/payment',
    methods=['GET', 'POST']
)
@login_required
@limiter.limit("10 per hour", methods=["POST"])
def course_payment(course_id):
    c = db.session.get(Course, course_id) or abort(404)

    if not c.is_published and not admin_only():
        abort(404)

    enrollment = Enrollment.query.filter_by(
        user_id=current_user.id,
        course_id=c.id
    ).first()

    if enrollment and enrollment.status == 'approved':
        flash('هذا الكورس مفعّل عندك بالفعل.', 'success')
        return redirect(url_for('course_detail', course_id=c.id))

    if not enrollment:
        enrollment = Enrollment(
            user_id=current_user.id,
            course_id=c.id,
            status='pending'
        )
        db.session.add(enrollment)
        db.session.commit()

    methods = get_supported_manual_payment_methods()

    latest_payment = CoursePayment.query.filter_by(
        user_id=current_user.id,
        course_id=c.id
    ).order_by(CoursePayment.id.desc()).first()

    if request.method == 'POST':
        try:
            method_id = int(request.form.get('payment_method_id') or 0)
        except ValueError:
            method_id = 0

        method = db.session.get(PaymentMethod, method_id)
        if not method or not method.is_active:
            flash('اختار طريقة دفع فعّالة.', 'error')
            return redirect(url_for('course_payment', course_id=c.id))

        transaction_id = (
            request.form.get('transaction_id') or ''
        ).strip()
        note = (request.form.get('note') or '').strip()
        proof_file = request.files.get('proof')

        if proof_file and proof_file.filename:
            if not allowed_payment_proof(proof_file.filename):
                flash('صيغة الإثبات غير مدعومة. استخدم JPG أو PNG أو WEBP أو PDF.', 'error')
                return redirect(url_for('course_payment', course_id=c.id))

            proof_file.stream.seek(0, os.SEEK_END)
            proof_size = proof_file.stream.tell()
            proof_file.stream.seek(0)
            if proof_size > MAX_PAYMENT_PROOF_SIZE:
                flash('حجم إثبات الدفع يجب أن لا يتجاوز 10MB.', 'error')
                return redirect(url_for('course_payment', course_id=c.id))

        if not transaction_id and not (proof_file and proof_file.filename):
            flash('اكتب رقم العملية أو ارفع إثبات الدفع.', 'error')
            return redirect(url_for('course_payment', course_id=c.id))

        existing_pending = CoursePayment.query.filter_by(
            user_id=current_user.id,
            course_id=c.id,
            status='pending'
        ).first()
        if existing_pending:
            flash('عندك طلب دفع قيد المراجعة بالفعل. انتظر مراجعة الإدارة قبل إرسال طلب جديد.', 'error')
            return redirect(url_for('course_payment', course_id=c.id))

        proof_filename = ''
        if proof_file and proof_file.filename:
            proof_filename = save_payment_proof(proof_file) or ''
            if not proof_filename:
                flash('تعذر التحقق من ملف إثبات الدفع.', 'error')
                return redirect(url_for('course_payment', course_id=c.id))

        payment = CoursePayment(
            user_id=current_user.id,
            course_id=c.id,
            enrollment_id=enrollment.id,
            payment_method_id=method.id,
            amount=c.price or '',
            transaction_id=transaction_id,
            proof_filename=proof_filename,
            note=note,
            status='pending'
        )
        db.session.add(payment)
        db.session.commit()

        flash('تم إرسال إثبات الدفع. الطلب الآن بانتظار مراجعة الإدارة.', 'success')
        return redirect(url_for('course_payment', course_id=c.id))

    return render_template(
        'course_payment.html',
        course=c,
        enrollment=enrollment,
        payment_methods=methods,
        latest_payment=latest_payment
    )


@app.route('/admin/payment-proof/<int:payment_id>')
@login_required
def admin_payment_proof(payment_id):
    if not admin_only():
        abort(403)

    payment = db.session.get(CoursePayment, payment_id) or abort(404)
    if not payment.proof_filename:
        abort(404)

    return send_from_directory(
        app.config['PAYMENT_PROOF_FOLDER'],
        os.path.basename(payment.proof_filename),
        conditional=True
    )


@app.route('/admin/payments')
@login_required
def admin_payments():
    if not admin_only():
        abort(403)

    payments = CoursePayment.query.order_by(
        CoursePayment.id.desc()
    ).all()

    return render_template(
        'admin_payments.html',
        payments=payments
    )


@app.route(
    '/admin/payment/<int:payment_id>/approve',
    methods=['POST']
)
@login_required
def admin_payment_approve(payment_id):
    if not admin_only():
        abort(403)

    payment = db.session.get(CoursePayment, payment_id) or abort(404)
    if payment.status != 'pending':
        flash('هذا الطلب تمت مراجعته مسبقاً.', 'error')
        return redirect(url_for('admin_payments'))

    enrollment = db.session.get(Enrollment, payment.enrollment_id)
    if not enrollment:
        abort(404)

    payment.status = 'approved'
    payment.admin_note = (request.form.get('admin_note') or '').strip()
    enrollment.status = 'approved'
    db.session.commit()

    flash('تم قبول الدفعة وتفعيل الكورس للزبون.', 'success')
    return redirect(url_for('admin_payments'))


@app.route(
    '/admin/payment/<int:payment_id>/reject',
    methods=['POST']
)
@login_required
def admin_payment_reject(payment_id):
    if not admin_only():
        abort(403)

    payment = db.session.get(CoursePayment, payment_id) or abort(404)
    if payment.status != 'pending':
        flash('هذا الطلب تمت مراجعته مسبقاً.', 'error')
        return redirect(url_for('admin_payments'))

    payment.status = 'rejected'
    payment.admin_note = (request.form.get('admin_note') or '').strip()
    db.session.commit()

    flash('تم رفض الدفعة. يبقى الكورس مقفولاً ويمكن للزبون إعادة الإرسال.', 'success')
    return redirect(url_for('admin_payments'))


@app.route('/admin/service-orders')
@login_required
def admin_service_orders():
    if not admin_only():
        abort(403)
    orders = ServiceOrder.query.order_by(ServiceOrder.id.desc()).all()
    return render_template('admin_service_orders.html', orders=orders)


@app.route('/admin/service-order/<int:order_id>/request-attachment')
@login_required
def admin_service_order_attachment(order_id):
    if not admin_only():
        abort(403)
    order = db.session.get(ServiceOrder, order_id) or abort(404)
    if not order.request_attachment_filename:
        abort(404)
    return send_from_directory(
        app.config['PAYMENT_PROOF_FOLDER'],
        os.path.basename(order.request_attachment_filename),
        as_attachment=True,
        download_name=f'service-order-{order.id}-account-status',
        conditional=True,
    )


@app.route('/admin/service-order/<int:order_id>/<action>', methods=['POST'])
@login_required
def admin_service_order_status(order_id, action):
    if not admin_only():
        abort(403)
    order = db.session.get(ServiceOrder, order_id) or abort(404)
    transitions = {
        'pending': {'approve': 'approved', 'reject': 'rejected'},
        'approved': {'complete': 'completed', 'refund': 'refunded'},
        'completed': {'refund': 'refunded'},
    }
    next_status = transitions.get(order.status, {}).get(action)
    if not next_status:
        flash('هذا الانتقال غير مسموح أو الطلب تمت معالجته مسبقاً.', 'error')
        return redirect(url_for('admin_service_orders'))

    wallet_paid = order.payment_method_id is None and order.transaction_id == 'RABBIT WALLET'
    if wallet_paid and action in {'reject', 'refund'}:
        existing_refund = WalletTransaction.query.filter_by(
            user_id=order.user_id,
            transaction_type='refund',
            reference_type='service_order_refund',
            reference_id=order.id
        ).first()
        if not existing_refund:
            purchase = WalletTransaction.query.filter_by(
                user_id=order.user_id,
                transaction_type='purchase',
                reference_type='service_order',
                reference_id=order.id
            ).first()
            if purchase and purchase.amount_iqd < 0:
                db.session.add(WalletTransaction(
                    user_id=order.user_id,
                    transaction_type='refund',
                    amount_iqd=-purchase.amount_iqd,
                    reference_type='service_order_refund',
                    reference_id=order.id,
                    note=f'استرجاع مبلغ طلب خدمة #{order.id}'[:250]
                ))

    order.status = next_status
    order.admin_note = (request.form.get('admin_note') or '').strip()[:250]
    db.session.commit()
    flash('تم تحديث حالة طلب الخدمة.', 'success')
    return redirect(url_for('admin_service_orders'))


@app.route('/wallet/top-up', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def wallet_top_up():
    methods = get_supported_manual_payment_methods()
    if request.method == 'POST':
        try:
            amount_iqd = int(request.form.get('amount_iqd') or 0)
            payment_method_id = int(request.form.get('payment_method_id') or 0)
        except ValueError:
            amount_iqd = 0
            payment_method_id = 0
        transaction_id = (request.form.get('transaction_id') or '').strip()
        method = db.session.get(PaymentMethod, payment_method_id)
        if amount_iqd < 1000:
            flash('أقل مبلغ للشحن هو 1,000 د.ع.', 'error')
            return redirect(url_for('wallet_top_up'))
        if not method or not method.is_active:
            flash('اختر طريقة دفع متاحة.', 'error')
            return redirect(url_for('wallet_top_up'))
        if not transaction_id or len(transaction_id) > 250:
            flash('أدخل رقم عملية التحويل.', 'error')
            return redirect(url_for('wallet_top_up'))
        proof = save_payment_proof(request.files.get('payment_proof'))
        if not proof:
            flash('ارفع إثبات الدفع.', 'error')
            return redirect(url_for('wallet_top_up'))
        db.session.add(WalletTopUp(user_id=current_user.id, payment_method_id=method.id, amount_iqd=amount_iqd, transaction_id=transaction_id, proof_filename=proof, status='pending'))
        db.session.commit()
        flash('تم إرسال طلب شحن الرصيد للمراجعة.', 'success')
        return redirect(url_for('account'))
    return render_template('wallet_top_up.html', payment_methods=methods)


@app.route('/admin/wallet-topups')
@login_required
def admin_wallet_topups():
    if not admin_only():
        abort(403)
    topups = WalletTopUp.query.order_by(WalletTopUp.id.desc()).all()
    return render_template('admin_wallet_topups.html', topups=topups)


@app.route('/admin/wallet-topup/<int:topup_id>/<action>', methods=['POST'])
@login_required
def admin_wallet_topup_action(topup_id, action):
    if not admin_only():
        abort(403)
    topup = db.session.get(WalletTopUp, topup_id) or abort(404)
    if topup.status != 'pending':
        flash('هذا الطلب تمت مراجعته مسبقاً.', 'error')
        return redirect(url_for('admin_wallet_topups'))
    note = (request.form.get('admin_note') or '').strip()[:250]
    if action == 'approve':
        topup.status = 'approved'
        topup.admin_note = note
        topup.reviewed_at = datetime.utcnow()
        db.session.add(WalletTransaction(user_id=topup.user_id, transaction_type='topup', amount_iqd=topup.amount_iqd, reference_type='wallet_topup', reference_id=topup.id, note='شحن رصيد معتمد'))
    elif action == 'reject':
        topup.status = 'rejected'
        topup.admin_note = note
        topup.reviewed_at = datetime.utcnow()
    else:
        abort(404)
    db.session.commit()
    flash('تم تحديث طلب شحن الرصيد.', 'success')
    return redirect(url_for('admin_wallet_topups'))


@app.route('/admin/wallet-payment-proof/<path:filename>')
@login_required
def admin_wallet_payment_proof(filename):
    if not admin_only():
        abort(403)
    safe_name = os.path.basename(filename)
    if safe_name != filename:
        abort(404)
    file_path = os.path.join(app.config['PAYMENT_PROOF_FOLDER'], safe_name)
    if not os.path.isfile(file_path):
        abort(404)
    return send_from_directory(app.config['PAYMENT_PROOF_FOLDER'], safe_name, conditional=True)


# =========================
# Customer Account
# =========================

@app.route('/account')
@login_required
def account():
    enrollments = Enrollment.query.filter_by(
        user_id=current_user.id
    ).order_by(Enrollment.id.desc()).all()

    course_items = []

    for enrollment in enrollments:
        latest_payment = CoursePayment.query.filter_by(
            user_id=current_user.id,
            course_id=enrollment.course_id
        ).order_by(CoursePayment.id.desc()).first()

        course_items.append({
            'enrollment': enrollment,
            'course': enrollment.course,
            'payment': latest_payment
        })

    payments = CoursePayment.query.filter_by(
        user_id=current_user.id
    ).order_by(CoursePayment.id.desc()).all()

    service_requests = ServiceRequest.query.filter_by(
        username=current_user.username
    ).order_by(ServiceRequest.id.desc()).all()

    service_orders = ServiceOrder.query.filter_by(
        user_id=current_user.id
    ).order_by(ServiceOrder.id.desc()).all()

    return render_template(
        'account.html',
        course_items=course_items,
        payments=payments,
        service_requests=service_requests,
        service_orders=service_orders,
        store_orders=StoreOrder.query.filter_by(user_id=current_user.id).order_by(StoreOrder.id.desc()).all(),
        wallet_topups=WalletTopUp.query.filter_by(user_id=current_user.id).order_by(WalletTopUp.id.desc()).all(),
        wallet_transactions=WalletTransaction.query.filter_by(user_id=current_user.id).order_by(WalletTransaction.id.desc()).limit(20).all(),
        balance=f'{wallet_balance_iqd(current_user.id):,} د.ع'
    )


# =========================
# Orders
# =========================

@app.route(
    '/order',
    methods=['POST']
)
@login_required
@limiter.limit("10 per hour")
def place_order():
    service_type = (request.form.get('service_type') or '').strip()
    details = (request.form.get('details') or '').strip()
    phone = (request.form.get('phone') or '').strip()

    if not service_type or not details or not phone:
        flash('أكمل تفاصيل الطلب ورقم التواصل.', 'error')
        return redirect(request.referrer or url_for('services'))

    if len(service_type) > 50 or len(details) > 2000 or len(phone) > 20:
        flash('بيانات الطلب أطول من الحد المسموح.', 'error')
        return redirect(request.referrer or url_for('services'))

    db.session.add(
        ServiceRequest(
            username=current_user.username,
            service_type=service_type,
            details=details,
            phone=phone
        )
    )
    db.session.commit()

    flash('تم إرسال طلبك بنجاح.', 'success')
    return redirect(url_for('account'))


# =========================
# Admin Panel
# =========================

@app.route('/admin')
@login_required
def admin_panel():

    if not admin_only():
        abort(403)

    return render_template(
        'admin.html',

        users=User.query.filter_by(
            is_admin=False
        ).all(),

        orders=ServiceRequest.query.order_by(
            ServiceRequest.id.desc()
        ).all(),

        course_count=Course.query.count(),

        lesson_count=Lesson.query.count(),

        enrollments=Enrollment.query.order_by(
            Enrollment.id.desc()
        ).all(),

        payment_method_count=PaymentMethod.query.count(),

        active_payment_method_count=PaymentMethod.query.filter_by(
            is_active=True
        ).count(),

        pending_payment_count=CoursePayment.query.filter_by(
            status='pending'
        ).count()
    )


@app.route('/admin/accounting/expense', methods=['POST'])
@login_required
def admin_accounting_expense():
    if not admin_only():
        abort(403)
    try:
        amount = int(request.form.get('amount_iqd') or 0)
        expense_date = datetime.strptime(request.form.get('expense_date') or '', '%Y-%m-%d')
    except (ValueError, TypeError):
        flash('تأكد من مبلغ وتاريخ المصروف.', 'error')
        return redirect(url_for('admin_accounting'))
    category = (request.form.get('category') or 'مصروف عام').strip()[:80]
    note = (request.form.get('note') or '').strip()[:250]
    if amount <= 0:
        flash('مبلغ المصروف يجب أن يكون أكبر من صفر.', 'error')
        return redirect(url_for('admin_accounting'))
    db.session.add(AccountingExpense(amount_iqd=amount, category=category, note=note, expense_date=expense_date))
    db.session.commit()
    flash('تم تسجيل المصروف.', 'success')
    return redirect(url_for('admin_accounting', year=expense_date.year, month=expense_date.month))


@app.route('/admin/accounting/expense/<int:expense_id>/delete', methods=['POST'])
@login_required
def admin_accounting_expense_delete(expense_id):
    if not admin_only():
        abort(403)
    item = db.session.get(AccountingExpense, expense_id) or abort(404)
    year, month = item.expense_date.year, item.expense_date.month
    db.session.delete(item)
    db.session.commit()
    flash('تم حذف المصروف.', 'success')
    return redirect(url_for('admin_accounting', year=year, month=month))


@app.route('/admin/accounting')
@login_required
def admin_accounting():
    if not admin_only():
        abort(403)
    now = datetime.utcnow()
    try:
        year = int(request.args.get('year') or now.year)
        month = int(request.args.get('month') or now.month)
    except ValueError:
        year, month = now.year, now.month
    if month < 1 or month > 12 or year < 2020 or year > 2100:
        year, month = now.year, now.month
    start = datetime(year, month, 1)
    end = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

    topups = WalletTopUp.query.filter(
        WalletTopUp.status == 'approved',
        WalletTopUp.reviewed_at >= start,
        WalletTopUp.reviewed_at < end
    ).all()
    cash_in = sum(x.amount_iqd for x in topups)

    wallet_sales = WalletTransaction.query.filter(
        WalletTransaction.transaction_type == 'purchase',
        WalletTransaction.created_at >= start,
        WalletTransaction.created_at < end
    ).all()
    sales_iqd = sum(-x.amount_iqd for x in wallet_sales if x.amount_iqd < 0)

    refunds = WalletTransaction.query.filter(
        WalletTransaction.transaction_type == 'refund',
        WalletTransaction.created_at >= start,
        WalletTransaction.created_at < end
    ).all()
    refunds_iqd = sum(x.amount_iqd for x in refunds if x.amount_iqd > 0)
    net_sales_iqd = sales_iqd - refunds_iqd
    expenses = AccountingExpense.query.filter(
        AccountingExpense.expense_date >= start,
        AccountingExpense.expense_date < end
    ).order_by(AccountingExpense.expense_date.desc(), AccountingExpense.id.desc()).all()
    expenses_iqd = sum(x.amount_iqd for x in expenses)
    profit_iqd = net_sales_iqd - expenses_iqd

    daily = {}
    for tx in wallet_sales:
        if tx.amount_iqd < 0:
            day = tx.created_at.day
            daily[day] = daily.get(day, 0) + (-tx.amount_iqd)
    for tx in refunds:
        if tx.amount_iqd > 0:
            day = tx.created_at.day
            daily[day] = daily.get(day, 0) - tx.amount_iqd

    transactions = sorted(
        [{'date': x.created_at, 'kind': 'بيع', 'amount': -x.amount_iqd, 'note': x.note} for x in wallet_sales if x.amount_iqd < 0] +
        [{'date': x.created_at, 'kind': 'استرجاع', 'amount': -x.amount_iqd, 'note': x.note} for x in refunds if x.amount_iqd > 0],
        key=lambda x: x['date'], reverse=True
    )

    return render_template('admin_accounting.html',
        year=year, month=month, cash_in=cash_in, sales_iqd=sales_iqd,
        refunds_iqd=refunds_iqd, net_sales_iqd=net_sales_iqd,
        expenses_iqd=expenses_iqd, profit_iqd=profit_iqd, expenses=expenses,
        daily=sorted(daily.items()), transactions=transactions)


@app.route('/admin/launch-check')
@login_required
def admin_launch_check():
    if not admin_only():
        abort(403)
    courses = Course.query.filter_by(is_published=True).all()
    services = Service.query.filter_by(is_active=True).all()
    store_items = StoreItem.query.filter_by(is_active=True).all()
    methods = get_supported_manual_payment_methods()
    checks = [
        ('طرق الدفع', bool(methods), f'{len(methods)} طريقة مفعلة' if methods else 'أضف طريقة دفع واحدة على الأقل'),
        ('الكورسات المنشورة', bool(courses), f'{len(courses)} كورس منشور' if courses else 'لا يوجد كورس منشور'),
        ('الفيديو التجريبي', any(any(l.is_preview and l.video_url for l in c.lessons) for c in courses),
         'يوجد فيديو تجريبي في كورس منشور' if any(any(l.is_preview and l.video_url for l in c.lessons) for c in courses) else 'أضف فيديو تجريبي قبل الإطلاق'),
        ('الخدمات', bool(services), f'{len(services)} خدمة ظاهرة' if services else 'لا توجد خدمات ظاهرة'),
        ('المتجر', bool(store_items), f'{len(store_items)} عرض ظاهر' if store_items else 'أضف عروض المتجر عند الجاهزية'),
    ]
    return render_template('admin_launch_check.html', checks=checks)


# =========================
# Admin Payment Methods
# =========================

@app.route(
    '/admin/payment-methods',
    methods=['GET', 'POST']
)
@login_required
def admin_payment_methods():

    if not admin_only():
        abort(403)

    if request.method == 'POST':

        name = (
            request.form.get('name')
            or ''
        ).strip()

        payment_type = (
            request.form.get('payment_type')
            or 'manual'
        ).strip()

        account_name = (
            request.form.get('account_name')
            or ''
        ).strip()

        account_number = (
            request.form.get('account_number')
            or ''
        ).strip()

        network = (
            request.form.get('network')
            or ''
        ).strip()

        instructions = (
            request.form.get('instructions')
            or ''
        ).strip()

        try:
            position = int(
                request.form.get('position')
                or 1
            )
        except ValueError:
            position = 1

        if not name:
            flash(
                'اكتب اسم طريقة الدفع.',
                'error'
            )

            return redirect(
                url_for('admin_payment_methods')
            )

        method = PaymentMethod(
            name=name,
            payment_type=payment_type,
            account_name=account_name,
            account_number=account_number,
            network=network,
            instructions=instructions,
            is_active=bool(
                request.form.get('is_active')
            ),
            position=position
        )

        db.session.add(method)
        db.session.commit()

        flash(
            'تمت إضافة طريقة الدفع بنجاح.',
            'success'
        )

        return redirect(
            url_for('admin_payment_methods')
        )

    methods = PaymentMethod.query.order_by(
        PaymentMethod.position.asc(),
        PaymentMethod.id.asc()
    ).all()

    return render_template(
        'admin_payment_methods.html',
        payment_methods=methods
    )


@app.route(
    '/admin/payment-method/<int:method_id>/edit',
    methods=['POST']
)
@login_required
def admin_payment_method_edit(method_id):

    if not admin_only():
        abort(403)

    method = db.session.get(
        PaymentMethod,
        method_id
    ) or abort(404)

    name = (
        request.form.get('name')
        or ''
    ).strip()

    if not name:
        flash(
            'اسم طريقة الدفع مطلوب.',
            'error'
        )

        return redirect(
            url_for('admin_payment_methods')
        )

    method.name = name

    method.payment_type = (
        request.form.get('payment_type')
        or 'manual'
    ).strip()

    method.account_name = (
        request.form.get('account_name')
        or ''
    ).strip()

    method.account_number = (
        request.form.get('account_number')
        or ''
    ).strip()

    method.network = (
        request.form.get('network')
        or ''
    ).strip()

    method.instructions = (
        request.form.get('instructions')
        or ''
    ).strip()

    try:
        method.position = int(
            request.form.get('position')
            or 1
        )
    except ValueError:
        method.position = 1

    method.is_active = bool(
        request.form.get('is_active')
    )

    db.session.commit()

    flash(
        'تم حفظ تعديلات طريقة الدفع.',
        'success'
    )

    return redirect(
        url_for('admin_payment_methods')
    )


@app.route(
    '/admin/payment-method/<int:method_id>/toggle',
    methods=['POST']
)
@login_required
def admin_payment_method_toggle(method_id):

    if not admin_only():
        abort(403)

    method = db.session.get(
        PaymentMethod,
        method_id
    ) or abort(404)

    method.is_active = not method.is_active

    db.session.commit()

    if method.is_active:
        flash(
            'تم تفعيل طريقة الدفع.',
            'success'
        )
    else:
        flash(
            'تم تعطيل طريقة الدفع.',
            'success'
        )

    return redirect(
        url_for('admin_payment_methods')
    )


@app.route(
    '/admin/payment-method/<int:method_id>/delete',
    methods=['POST']
)
@login_required
def admin_payment_method_delete(method_id):

    if not admin_only():
        abort(403)

    method = db.session.get(
        PaymentMethod,
        method_id
    ) or abort(404)

    has_payments = CoursePayment.query.filter_by(
        payment_method_id=method.id
    ).first()

    if has_payments:

        method.is_active = False
        db.session.commit()

        flash(
            'لا يمكن حذف هذه الطريقة لأنها مرتبطة بدفعات سابقة، لذلك تم تعطيلها بدلاً من حذفها.',
            'error'
        )

    else:

        db.session.delete(method)
        db.session.commit()

        flash(
            'تم حذف طريقة الدفع.',
            'success'
        )

    return redirect(
        url_for('admin_payment_methods')
    )


# =========================
# Course Enrollment Approval
# =========================

@app.route(
    '/admin/enrollment/<int:enrollment_id>/approve',
    methods=['POST']
)
@login_required
def approve_enrollment(enrollment_id):

    if not admin_only():
        abort(403)

    enrollment = db.session.get(
        Enrollment,
        enrollment_id
    ) or abort(404)

    enrollment.status = 'approved'

    db.session.commit()

    flash(
        'تم تفعيل الكورس للمستخدم بنجاح.'
    )

    return redirect(
        url_for('admin_panel')
    )


# =========================
# Admin Courses
# =========================

@app.route('/admin/courses')
@login_required
def admin_courses():

    if not admin_only():

        abort(403)

    return render_template(
        'admin_courses.html',
        courses=Course.query.order_by(
            Course.id
        ).all()
    )


@app.route(
    '/admin/course/new',
    methods=['GET', 'POST']
)
@login_required
def admin_course_new():

    if not admin_only():

        abort(403)

    if request.method == 'POST':

        c = Course(

            title=request.form['title'],

            category=request.form[
                'category'
            ],

            level=request.form[
                'level'
            ],

            price=request.form.get(
                'price',
                'قريباً'
            ),
            price_iqd=parse_iqd_price(request.form.get('price_iqd')),

            instructor=request.form.get(
                'instructor',
                ''
            ),

            description=request.form.get(
                'description',
                ''
            ),

            is_published=bool(
                request.form.get(
                    'is_published'
                )
            )
        )

        db.session.add(c)
        db.session.commit()

        flash(
            'تمت إضافة الدورة.'
        )

        return redirect(
            url_for('admin_courses')
        )

    return render_template(
        'admin_course_form.html',
        course=None
    )


@app.route(
    '/admin/course/<int:course_id>/edit',
    methods=['GET', 'POST']
)
@login_required
def admin_course_edit(course_id):

    if not admin_only():

        abort(403)

    c = db.session.get(
        Course,
        course_id
    ) or abort(404)

    if request.method == 'POST':

        c.title = request.form[
            'title'
        ]

        c.category = request.form[
            'category'
        ]

        c.level = request.form[
            'level'
        ]

        c.price = request.form.get(
            'price',
            ''
        )
        c.price_iqd = parse_iqd_price(request.form.get('price_iqd'))

        c.instructor = request.form.get(
            'instructor',
            ''
        )

        c.description = request.form.get(
            'description',
            ''
        )

        c.is_published = bool(
            request.form.get(
                'is_published'
            )
        )

        db.session.commit()

        flash(
            'تم حفظ التعديلات.'
        )

        return redirect(
            url_for('admin_courses')
        )

    return render_template(
        'admin_course_form.html',
        course=c
    )


# =========================
# Admin Lessons + Video Upload
# =========================

@app.route(
    '/admin/course/<int:course_id>/lessons',
    methods=['GET', 'POST']
)
@login_required
def admin_lessons(course_id):

    if not admin_only():

        abort(403)

    c = db.session.get(
        Course,
        course_id
    ) or abort(404)

    if request.method == 'POST':

        video_url = (
            request.form.get(
                'video_url',
                ''
            ).strip()
        )

        video_file = request.files.get(
            'video_file'
        )

        if (
            video_file
            and video_file.filename
        ):

            if not allowed_video(
                video_file.filename
            ):

                flash(
                    'صيغة الفيديو غير مدعومة. استخدم MP4 أو WEBM أو MOV أو M4V.'
                )

                return redirect(
                    url_for(
                        'admin_lessons',
                        course_id=c.id
                    )
                )

            uploaded_url = save_video(
                video_file
            )

            if uploaded_url:

                video_url = uploaded_url

        if not video_url:

            flash(
                'اختار فيديو من الكمبيوتر أو ضع رابط فيديو.'
            )

            return redirect(
                url_for(
                    'admin_lessons',
                    course_id=c.id
                )
            )

        lesson = Lesson(

            course_id=c.id,

            title=request.form[
                'title'
            ],

            video_url=video_url,

            duration=request.form.get(
                'duration',
                ''
            ),

            position=int(
                request.form.get(
                    'position'
                )
                or
                len(c.lessons) + 1
            ),

            is_preview=bool(
                request.form.get(
                    'is_preview'
                )
            )
        )

        db.session.add(lesson)

        db.session.commit()

        flash(
            'تمت إضافة الدرس والفيديو بنجاح.'
        )

        return redirect(
            url_for(
                'admin_lessons',
                course_id=c.id
            )
        )

    return render_template(
        'admin_lessons.html',
        course=c
    )


@app.route('/admin/lesson/<int:lesson_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_lesson_edit(lesson_id):
    if not admin_only():
        abort(403)
    lesson = db.session.get(Lesson, lesson_id) or abort(404)
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        if not title:
            flash('عنوان الدرس مطلوب.', 'error')
            return redirect(url_for('admin_lesson_edit', lesson_id=lesson.id))
        try:
            position = max(1, int(request.form.get('position') or lesson.position or 1))
        except ValueError:
            position = lesson.position or 1
        video_url = (request.form.get('video_url') or lesson.video_url or '').strip()
        video_file = request.files.get('video_file')
        if video_file and video_file.filename:
            if not allowed_video(video_file.filename):
                flash('صيغة الفيديو غير مدعومة.', 'error')
                return redirect(url_for('admin_lesson_edit', lesson_id=lesson.id))
            uploaded_url = save_video(video_file)
            if uploaded_url:
                if lesson.video_url and '://' not in lesson.video_url:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(lesson.video_url))
                    if os.path.isfile(old_path):
                        try:
                            os.remove(old_path)
                        except OSError:
                            pass
                video_url = uploaded_url
        lesson.title = title
        lesson.video_url = video_url
        lesson.duration = (request.form.get('duration') or '').strip()[:30]
        lesson.position = position
        lesson.is_preview = bool(request.form.get('is_preview'))
        db.session.commit()
        flash('تم تحديث الدرس.', 'success')
        return redirect(url_for('admin_lessons', course_id=lesson.course_id))
    return render_template('admin_lesson_edit.html', lesson=lesson)


@app.route('/admin/course/<int:course_id>/lessons/reorder', methods=['POST'])
@login_required
def admin_lessons_reorder(course_id):
    if not admin_only():
        abort(403)
    course = db.session.get(Course, course_id) or abort(404)
    ordered = sorted(course.lessons, key=lambda x: (x.position, x.id))
    for index, lesson in enumerate(ordered, 1):
        lesson.position = index
    db.session.commit()
    flash('تم ترتيب الدروس بالتسلسل.', 'success')
    return redirect(url_for('admin_lessons', course_id=course.id))


# =========================
# Delete Lesson
# =========================

@app.route(
    '/admin/lesson/<int:lesson_id>/delete',
    methods=['POST']
)
@login_required
def admin_lesson_delete(lesson_id):

    if not admin_only():

        abort(403)

    lesson = db.session.get(
        Lesson,
        lesson_id
    ) or abort(404)

    course_id = lesson.course_id

    if lesson.video_url and '://' not in lesson.video_url:
        filename = os.path.basename(lesson.video_url)
        file_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            filename
        )

        if os.path.isfile(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

    db.session.delete(
        lesson
    )

    db.session.commit()

    return redirect(
        url_for(
            'admin_lessons',
            course_id=course_id
        )
    )



# =========================
# Logout
# =========================

@app.route('/logout', methods=['POST'])
@login_required
def logout():

    logout_user()

    return redirect(
        url_for('home')
    )


# =========================
# Run
# =========================

# =========================
# Initialize Database
# =========================

with app.app_context():
    # Add new account fields to an existing database without deleting users.
    from sqlalchemy import inspect, text as sql_text

    inspector = inspect(db.engine)

    if 'user' in inspector.get_table_names():

        existing_columns = {
            column['name']
            for column
            in inspector.get_columns('user')
        }

        account_columns = {
            'full_name': 'VARCHAR(120)',
            'email': 'VARCHAR(254)',
            'phone': 'VARCHAR(20)',
            'email_verified': 'BOOLEAN NOT NULL DEFAULT FALSE',
            'phone_verified': 'BOOLEAN NOT NULL DEFAULT FALSE',
        }

        with db.engine.begin() as connection:

            for column_name, column_type in account_columns.items():

                if column_name not in existing_columns:
                    connection.execute(
                        sql_text(
                            f'ALTER TABLE "user" '
                            f'ADD COLUMN {column_name} {column_type}'
                        )
                    )

            connection.execute(
                sql_text(
                    'CREATE UNIQUE INDEX IF NOT EXISTS '
                    'ix_user_email_unique ON "user" (email)'
                )
            )

            connection.execute(
                sql_text(
                    'CREATE UNIQUE INDEX IF NOT EXISTS '
                    'ix_user_phone_unique ON "user" (phone)'
                )
            )

    db.create_all()

    # Add package details to existing databases without changing existing packages.
    package_inspector = inspect(db.engine)
    if 'service_package' in package_inspector.get_table_names():
        package_columns = {
            column['name'] for column in package_inspector.get_columns('service_package')
        }
        if 'description' not in package_columns:
            with db.engine.begin() as connection:
                connection.execute(
                    sql_text("ALTER TABLE service_package ADD COLUMN description TEXT NOT NULL DEFAULT ''")
                )
        if 'group_key' not in package_columns:
            with db.engine.begin() as connection:
                connection.execute(
                    sql_text("ALTER TABLE service_package ADD COLUMN group_key VARCHAR(60) NOT NULL DEFAULT ''")
                )

    # Separate any package price and details that were pasted into its label.
    package_label_migration = 'split_package_label_details_v2'
    if db.session.get(CatalogMigration, package_label_migration) is None:
        for package in ServicePackage.query.all():
            label = (package.label or '').strip()
            amount = f'{package.price_iqd:,}'
            price_match = re.search(
                rf'(?<!\d){re.escape(amount)}\s*(?:د\.?\s*ع|دينار(?:\s+عراقي)?)',
                label
            ) if amount else None
            if price_match:
                clean_label = label[:price_match.start()].rstrip(' —–-:،')
                details = label[price_match.end():].strip(' —–-:،')
                if clean_label:
                    package.label = clean_label[:120]
                    if not package.description and details:
                        package.description = details[:2000]
        db.session.add(CatalogMigration(key=package_label_migration))
        db.session.commit()

    package_copy_migration = 'repair_service_package_copy_v1'
    if db.session.get(CatalogMigration, package_copy_migration) is None:
        for package in ServicePackage.query.all():
            if (package.label or '').startswith('اقة '):
                package.label = 'ب' + package.label
            if (package.description or '').endswith('إعداد خط'):
                package.description = package.description[:-len('إعداد خط')] + 'إعداد خطة تسويقية للمشروع.'
        db.session.add(CatalogMigration(key=package_copy_migration))
        db.session.commit()

    # Keep ServiceOrder compatible with production databases created before
    # follower packages and price snapshots were introduced.
    inspector = inspect(db.engine)
    if 'service_order' in inspector.get_table_names():
        service_order_columns = {
            column['name']
            for column in inspector.get_columns('service_order')
        }
        service_order_additions = {
            'service_package_id': 'INTEGER',
            'package_label': "VARCHAR(120) DEFAULT ''",
            'amount': "VARCHAR(60) DEFAULT ''",
            'request_attachment_filename': "VARCHAR(250) DEFAULT ''",
            'payment_provider': "VARCHAR(30) DEFAULT ''",
            'gateway_invoice_id': "VARCHAR(120) DEFAULT ''",
            'gateway_payment_id': "VARCHAR(120) DEFAULT ''",
        }
        with db.engine.begin() as connection:
            for column_name, column_type in service_order_additions.items():
                if column_name not in service_order_columns:
                    connection.execute(
                        sql_text(
                            f'ALTER TABLE service_order '
                            f'ADD COLUMN {column_name} {column_type}'
                        )
                    )

    inspector = inspect(db.engine)
    if 'store_order' in inspector.get_table_names():
        store_order_columns = {
            column['name'] for column in inspector.get_columns('store_order')
        }
        store_order_additions = {
            'payment_method_id': 'INTEGER',
            'transaction_id': "VARCHAR(250) DEFAULT ''",
            'refund_account': "VARCHAR(250) DEFAULT ''",
            'proof_filename': "VARCHAR(250) DEFAULT ''",
            'payment_provider': "VARCHAR(30) DEFAULT ''",
            'gateway_invoice_id': "VARCHAR(120) DEFAULT ''",
            'gateway_payment_id': "VARCHAR(120) DEFAULT ''",
        }
        with db.engine.begin() as connection:
            for column_name, column_type in store_order_additions.items():
                if column_name not in store_order_columns:
                    connection.execute(sql_text(
                        f'ALTER TABLE store_order ADD COLUMN {column_name} {column_type}'
                    ))

    inspector = inspect(db.engine)
    with db.engine.begin() as connection:
        if 'service' in inspector.get_table_names():
            cols = {c['name'] for c in inspector.get_columns('service')}
            if 'price_iqd' not in cols:
                connection.execute(sql_text('ALTER TABLE service ADD COLUMN price_iqd INTEGER'))
        if 'store_item' in inspector.get_table_names():
            cols = {c['name'] for c in inspector.get_columns('store_item')}
            if 'price_iqd' not in cols:
                connection.execute(sql_text('ALTER TABLE store_item ADD COLUMN price_iqd INTEGER'))
        if 'service_order' in inspector.get_table_names():
            cols = {c['name'] for c in inspector.get_columns('service_order')}
            if 'payment_method_id' in cols:
                connection.execute(sql_text('ALTER TABLE service_order ALTER COLUMN payment_method_id DROP NOT NULL')) if db.engine.dialect.name == 'postgresql' else None

    inspector = inspect(db.engine)
    if 'course' in inspector.get_table_names():
        course_columns = {column['name'] for column in inspector.get_columns('course')}
        if 'price_iqd' not in course_columns:
            with db.engine.begin() as connection:
                connection.execute(sql_text('ALTER TABLE course ADD COLUMN price_iqd INTEGER'))

    seed_courses()
    seed_services_and_store()
    seed_account_recovery_service()

    admin_username = os.environ.get('ADMIN_USERNAME')
    admin_password = os.environ.get('ADMIN_PASSWORD')

    if admin_username and admin_password:
        admin_user = User.query.filter_by(username=admin_username).first()

        if not admin_user:
            admin_user = User(
                username=admin_username,
                email_or_phone='admin@rabbit.local',
                password=generate_password_hash(admin_password),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
        else:
            admin_user.is_admin = True
            admin_user.password = generate_password_hash(admin_password)
            db.session.commit()


# =========================
# Run Local Development
# =========================

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', '').lower() == 'true')
