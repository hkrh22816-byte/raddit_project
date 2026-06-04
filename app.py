from flask import Flask, render_template, request, redirect, url_for, session
import os

app = Flask(__name__)
# مفتاح الأمان السري لتشفير جلسات المستخدمين (ضروري لحماية لوحة الآدمن)
app.secret_key = "raddit_cyber_secret_key_123"

DB_FILE = "users.txt"
ORDERS_FILE = "orders.txt"

def load_users():
    users = {"admin": "pass123"}
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    u, p = line.split(":", 1)
                    users[u] = p
    return users

def save_user(username, password):
    with open(DB_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}:{password}\n")

def load_orders():
    orders = []
    if os.path.exists(ORDERS_FILE):
        with open(ORDERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "||" in line:
                    parts = line.split("||")
                    if len(parts) == 3:
                        orders.append({"customer": parts[0], "service": parts[1], "link": parts[2]})
    return orders

def save_order(customer, service, link):
    with open(ORDERS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{customer}||{service}||{link}\n")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        current_users = load_users()
        
        if username in current_users and current_users[username] == password:
            # تسجيل الجلسة وحفظ اسم المستخدم لحمايته
            session['user'] = username
            if username == "admin":
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard', user=username))
        else:
            message = "⚠️ بيانات الدخول غير صحيحة، أو الحساب غير مسجل."
    return render_template('login.html', message=message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ""
    success = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        current_users = load_users()
        if username in current_users:
            message = "⚠️ اسم المستخدم هذا مسجل مسبقاً، اختر اسماً آخر."
        else:
            save_user(username, password)
            success = "🎉 تم إنشاء حسابك بنجاح دائم! اذهب الآن لصفحة تسجيل الدخول."
    return render_template('register.html', message=message, success=success)

@app.route('/dashboard/<user>', methods=['GET', 'POST'])
def dashboard(user):
    # التحقق من أن المستخدم مسجل دخوله حالياً ولا يزور الرابط مباشرة
    if 'user' not in session or session['user'] != user:
        return redirect(url_for('login'))
        
    order_success = ""
    if request.method == 'POST':
        service = request.form.get('service_type')
        link = request.form.get('account_link')
        save_order(user, service, link)
        order_success = "تم استلام طلبك بنجاح وجارٍ مراجعته من قبل الإدارة الفنية!"
    return render_template('dashboard.html', username=user, order_success=order_success)

# المسار السري المؤمن بالكامل من الاختراقات المباشرة
@app.route('/secret-admin-panel')
def admin_panel():
    # فحص أمني: إذا لم يكن المستخدم "admin" يتم طرده فوراً إلى صفحة الدخول
    if 'user' not in session or session['user'] != 'admin':
        return "<h1>❌ خطأ أمني: غير مسموح لك بالدخول إلى هذه اللوحة!</h1>", 403
        
    all_orders = load_orders()
    return render_template('admin.html', orders=all_orders)

# مسار تسجيل الخروج لتنظيف الجلسة الأمنية
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)