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
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('X-Permitted-Cross-Domain-Policies', 'none')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault(
        'Permissions-Policy',
        'camera=(), microphone=(), geolocation=()'
    )
    response.headers.setdefault(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains'
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


# =========================
# Course Payments
# =========================

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

    return db.session.get(
        User,
        int(user_id)
    )


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


@app.route('/protected-video/<int:lesson_id>')
@login_required
def protected_video(lesson_id):

    lesson = db.session.get(
        Lesson,
        lesson_id
    ) or abort(404)

    if current_user.is_admin:
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


# =========================
# Home
# =========================

@app.route('/')
def home():

    return render_template(
        'index.html'
    )


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

            if method not in ('email', 'phone') or not contact:
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
        reg_contact=session.get('reg_contact')
    )


# =========================
# Courses
# =========================

@app.route('/courses')
def courses():

    q = request.args.get(
        'search',
        ''
    ).strip()

    cat = request.args.get(
        'category',
        ''
    ).strip()

    query = Course.query.filter_by(
        is_published=True
    )

    if cat:

        query = query.filter_by(
            category=cat
        )

    if q:

        query = query.filter(
            Course.title.contains(q)
            |
            Course.description.contains(q)
        )

    cats = [
        x[0]
        for x
        in db.session.query(
            Course.category
        ).distinct().all()
    ]

    return render_template(
        'courses.html',
        courses=query.order_by(
            Course.id
        ).all(),
        categories=cats,
        current_category=cat,
        search_query=q
    )


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

    return render_template(
        'course_detail.html',
        course=c,
        has_course_access=has_course_access,
        enrollment=enrollment
    )


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

    methods = PaymentMethod.query.filter_by(
        is_active=True
    ).order_by(
        PaymentMethod.position.asc(),
        PaymentMethod.id.asc()
    ).all()

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

    return render_template(
        'account.html',
        course_items=course_items,
        payments=payments,
        service_requests=service_requests,
        balance='0.00'
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

    db.session.add(
        ServiceRequest(
            username=current_user.username,
            service_type=request.form.get(
                'service_type',
                ''
            ),
            details=request.form.get(
                'details',
                ''
            ),
            phone=request.form.get(
                'phone',
                ''
            )
        )
    )

    db.session.commit()

    flash(
        'تم إرسال طلبك بنجاح.'
    )

    return redirect(
        url_for('home')
    )


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
    seed_courses()

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