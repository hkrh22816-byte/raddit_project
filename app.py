from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
import os
import uuid


app = Flask(__name__)

app.config['SECRET_KEY'] = 'Rabbit_Secret_Key_2026_Secure'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rabbit_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# =========================
# إعدادات رفع الفيديو
# =========================
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

ALLOWED_VIDEO_EXTENSIONS = {
    'mp4',
    'webm',
    'mov',
    'm4v'
}


db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'auth_page'
login_manager.init_app(app)


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

    email_or_phone = db.Column(
        db.String(100),
        unique=True,
        nullable=False
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
# Login / Register
# =========================

@app.route(
    '/auth',
    methods=['GET', 'POST']
)
def auth_page():

    if current_user.is_authenticated:
        return redirect(
            url_for('home')
        )

    if request.method == 'POST':

        action = request.form.get(
            'action'
        )

        username = (
            request.form.get(
                'username'
            )
            or ''
        ).strip()

        email_or_phone = (
            request.form.get(
                'email_or_phone'
            )
            or ''
        ).strip()

        password = (
            request.form.get(
                'password'
            )
            or ''
        )

        if action == 'register':

            if (
                not username
                or not email_or_phone
                or len(password) < 6
            ):

                flash(
                    'أكمل البيانات، وكلمة المرور يجب أن تكون 6 أحرف على الأقل.',
                    'error'
                )

                return redirect(
                    url_for('auth_page')
                )

            existing = User.query.filter(
                (User.username == username)
                |
                (
                    User.email_or_phone
                    == email_or_phone
                )
            ).first()

            if existing:

                flash(
                    'اسم المستخدم أو الرقم/الإيميل مسجل مسبقاً!',
                    'error'
                )

                return redirect(
                    url_for('auth_page')
                )

            user = User(
                username=username,
                email_or_phone=email_or_phone,
                password=generate_password_hash(
                    password
                ),
                is_admin=(
                    User.query.count() == 0
                )
            )

            db.session.add(
                user
            )

            db.session.commit()

            login_user(
                user
            )

            return redirect(
                url_for('home')
            )

        elif action == 'login':

            if (
                not username
                or not password
            ):

                flash(
                    'أدخل اسم المستخدم وكلمة المرور.',
                    'error'
                )

                return redirect(
                    url_for('auth_page')
                )

            user = User.query.filter_by(
                username=username
            ).first()

            if (
                user
                and check_password_hash(
                    user.password,
                    password
                )
            ):

                login_user(
                    user
                )

                return redirect(
                    url_for('home')
                )

            flash(
                'خطأ في اسم المستخدم أو كلمة المرور.',
                'error'
            )

            return redirect(
                url_for('auth_page')
            )

        else:

            flash(
                'حدث خطأ في الطلب، حاول مرة أخرى.',
                'error'
            )

            return redirect(
                url_for('auth_page')
            )

    return render_template(
        'login.html'
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

    c = db.session.get(
        Course,
        course_id
    ) or abort(404)

    enrollment = Enrollment.query.filter_by(
        user_id=current_user.id,
        course_id=c.id
    ).first()

    if enrollment:

        if enrollment.status == 'approved':
            flash(
                'هذا الكورس مفعّل عندك بالفعل.'
            )

        else:
            flash(
                'طلب اشتراكك موجود وبانتظار التفعيل.'
            )

    else:

        enrollment = Enrollment(
            user_id=current_user.id,
            course_id=c.id,
            status='pending'
        )

        db.session.add(enrollment)
        db.session.commit()

        flash(
            'تم إرسال طلب الاشتراك بنجاح. بعد تأكيد الدفع سيتم فتح الكورس.'
        )

    return redirect(
        url_for(
            'course_detail',
            course_id=c.id
        )
    )


# =========================
# Orders
# =========================

@app.route(
    '/order',
    methods=['POST']
)
@login_required
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
# Activate User
# =========================

@app.route(
    '/admin/activate/<int:user_id>'
)
@login_required
def activate_user(user_id):

    if not admin_only():

        abort(403)

    u = db.session.get(
        User,
        user_id
    )

    if u:

        u.has_paid_course = True

        db.session.commit()

    return redirect(
        url_for('admin_panel')
    )


# =========================
# Logout
# =========================

@app.route('/logout')
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
    db.create_all()
    seed_courses()


# =========================
# Run Local Development
# =========================

if __name__ == '__main__':
    app.run(debug=True)