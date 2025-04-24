import sqlite3
from flask import Flask, request, redirect, url_for, render_template, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!123'  # 세션에 필요, 실제 운영시에는 안전한 값으로 설정

# 신고 누적 차단 임계치
REPORT_THRESHOLD = 3

# 데이터베이스 파일 경로 설정
DB_PATH = os.path.join(os.getcwd(), "app.db")

def get_db():
    """요청 당 하나의 DB 연결을 가져옵니다."""
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용 가능하게
        db.execute("PRAGMA foreign_keys = ON")  # 외래키 제약조건 활성화
        g._database = db
    return db

@app.teardown_appcontext
def close_connection(exception):
    """요청 끝나면 DB 연결을 닫습니다."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 애플리케이션 시작 시 DB 초기화 (테이블 생성 및 기본 데이터 삽입)
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # 테이블 생성 (존재하지 않을 경우)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            is_blocked INTEGER NOT NULL DEFAULT 0,
            report_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            price INTEGER,
            seller_id INTEGER NOT NULL,
            is_blocked INTEGER NOT NULL DEFAULT 0,
            report_count INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    # 관리자 계정 생성 (기본 admin:admin 계정이 없을 경우 생성)
    cursor.execute("SELECT id FROM users WHERE is_admin=1")
    if cursor.fetchone() is None:
        admin_pass = generate_password_hash("admin")
        cursor.execute("INSERT OR REPLACE INTO users (username, password_hash, is_admin, is_blocked, report_count) VALUES (?, ?, 1, 0, 0)",
                       ("admin", admin_pass))
        conn.commit()
    conn.close()

# 애플리케이션 시작 시 DB 초기화 호출
init_db()

# Flask-Login 설정
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # login_required 실패 시 이동 페이지

class User(UserMixin):
    """Flask-Login이 사용할 User 클래스 (DB의 users 레코드와 연계)"""
    def __init__(self, id, username, password_hash, is_admin, is_blocked, report_count, balance):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = bool(is_admin)
        self.is_blocked = bool(is_blocked)
        self.report_count = report_count
        self.balance = balance

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    """세션에 저장된 사용자 ID로 User 객체 로드"""
    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        return None
    user = User(id=row["id"], username=row["username"], password_hash=row["password_hash"],
                is_admin=row["is_admin"], is_blocked=row["is_blocked"], report_count=row["report_count"], balance=row["balance"])
    return user

# 관리자 전용 데코레이터
from functools import wraps
def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
            flash("관리자 전용 페이지입니다.", "warning")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapped

# ------ 라우팅 및 뷰 함수 ------

@app.route('/')
def index():
    """메인 페이지 - 상품 목록 출력"""
    conn = get_db()
    # 차단되지 않은 상품과 차단되지 않은 판매자의 상품만 표시
    cur = conn.execute("""
        SELECT p.id, p.title, p.description, p.price, p.seller_id, u.username as seller_name
        FROM products p JOIN users u ON p.seller_id = u.id
        WHERE p.is_blocked = 0 AND u.is_blocked = 0
        ORDER BY p.id DESC
    """)
    products = cur.fetchall()
    return render_template('index.html', products=products)

@app.route('/register', methods=['GET','POST'])
def register():
    """회원가입"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력하세요.", "warning")
            return redirect(url_for('register'))
        conn = get_db()
        # 아이디 중복 확인
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            flash("이미 존재하는 사용자 이름입니다.", "warning")
            return redirect(url_for('register'))
        # 새 사용자 생성
        pass_hash = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password_hash, is_admin, is_blocked, report_count) VALUES (?, ?, 0, 0, 0)",
                     (username, pass_hash))
        conn.commit()
        flash("회원가입이 완료되었습니다. 로그인하세요.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db()

    if request.method == 'POST':
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # 비밀번호 변경 요청일 때
        if current_password and new_password and confirm_password:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
            if not check_password_hash(user["password_hash"], current_password):
                flash("현재 비밀번호가 일치하지 않습니다.", "danger")
            elif new_password != confirm_password:
                flash("새 비밀번호와 확인이 일치하지 않습니다.", "danger")
            else:
                new_hash = generate_password_hash(new_password)
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, current_user.id))
                conn.commit()
                flash("비밀번호가 변경되었습니다.", "success")
        else:
            flash("모든 항목을 입력하세요.", "warning")

    return render_template('profile.html')

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    conn = get_db()
    if request.method == 'POST':
        receiver_username = request.form.get("receiver")
        amount = int(request.form.get("amount"))

        if amount <= 0:
            flash("송금 금액은 0보다 커야 합니다.", "warning")
            return redirect(url_for('transfer'))

        receiver = conn.execute("SELECT * FROM users WHERE username = ?", (receiver_username,)).fetchone()
        if not receiver:
            flash("받는 사용자가 존재하지 않습니다.", "danger")
            return redirect(url_for('transfer'))

        sender = conn.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
        if sender["balance"] < amount:
            flash("잔액이 부족합니다.", "danger")
            return redirect(url_for('transfer'))

        # 잔액 갱신
        conn.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, current_user.id))
        conn.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, receiver["id"]))

        # 거래 기록
        conn.execute("INSERT INTO transactions (sender_id, receiver_id, amount) VALUES (?, ?, ?)",
                     (current_user.id, receiver["id"], amount))
        conn.commit()

        row = conn.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
        login_user(User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            is_admin=row["is_admin"],
            is_blocked=row["is_blocked"],
            report_count=row["report_count"],
            balance=row["balance"]
        ))

        flash(f"{receiver_username}님에게 {amount}원을 송금했습니다.", "success")
        return redirect(url_for('transfer'))

    return render_template("transfer.html")


@app.route('/login', methods=['GET','POST'])
def login():
    """로그인"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("아이디와 비밀번호를 입력하세요.", "warning")
            return redirect(url_for('login'))
        conn = get_db()
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            flash("존재하지 않는 사용자입니다.", "danger")
            return redirect(url_for('login'))
        # 비밀번호 검사
        stored_hash = row["password_hash"]
        if not check_password_hash(stored_hash, password):
            flash("비밀번호가 올바르지 않습니다.", "danger")
            return redirect(url_for('login'))
        # 차단된 계정인지 확인
        if row["is_blocked"]:
            flash("해당 계정은 이용 정지되었습니다.", "danger")
            return redirect(url_for('login'))
        # User 객체 생성 후 로그인
        user_obj = User(id=row["id"], username=row["username"], password_hash=row["password_hash"],
                        is_admin=row["is_admin"], is_blocked=row["is_blocked"], report_count=row["report_count"], balance=row["balance"])
        login_user(user_obj)
        flash(f"{user_obj.username}님 환영합니다!", "success")
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    """로그아웃"""
    logout_user()
    flash("로그아웃되었습니다.", "info")
    return redirect(url_for('index'))

@app.route('/product/new', methods=['GET','POST'])
@login_required
def create_product():
    """상품 등록"""
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        if not title or not price:
            flash("상품명과 가격은 필수입니다.", "warning")
            return redirect(url_for('create_product'))
        # 가격 숫자 변환 확인
        try:
            price_val = int(price)
        except ValueError:
            flash("가격은 숫자로 입력하세요.", "warning")
            return redirect(url_for('create_product'))
        conn = get_db()
        cur = conn.execute("INSERT INTO products (title, description, price, seller_id, is_blocked, report_count) VALUES (?, ?, ?, ?, 0, 0)",
                           (title, description or "", price_val, current_user.id))
        conn.commit()
        new_id = cur.lastrowid
        flash("상품이 등록되었습니다.", "success")
        return redirect(url_for('product_detail', product_id=new_id))
    return render_template('create_product.html')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """상품 상세 페이지"""
    conn = get_db()
    cur = conn.execute("""
        SELECT p.id, p.title, p.description, p.price, p.seller_id, p.is_blocked,
               u.username as seller_name, u.is_blocked as seller_blocked
        FROM products p JOIN users u ON p.seller_id = u.id
        WHERE p.id = ?
    """, (product_id,))
    row = cur.fetchone()
    if row is None:
        flash("상품을 찾을 수 없습니다.", "warning")
        return redirect(url_for('index'))
    # 차단된 상품 또는 판매자라면 접근 제한
    if row["is_blocked"] or row["seller_blocked"]:
        flash("차단된 상품입니다.", "danger")
        return redirect(url_for('index'))
    product = row  # sqlite3.Row 객체 (dict처럼 사용 가능)
    return render_template('product_detail.html', product=product)

@app.route('/chat/<int:user_id>', methods=['GET','POST'])
@login_required
def chat(user_id):
    """특정 사용자와의 채팅 페이지"""
    # 자기 자신과 채팅 시도 방지
    if user_id == current_user.id:
        flash("자신에게는 메시지를 보낼 수 없습니다.", "warning")
        return redirect(url_for('index'))
    conn = get_db()
    # 대화 대상 사용자 정보 확인
    cur = conn.execute("SELECT username, is_blocked FROM users WHERE id = ?", (user_id,))
    user_row = cur.fetchone()
    if user_row is None:
        flash("해당 사용자를 찾을 수 없습니다.", "warning")
        return redirect(url_for('index'))
    target_username = user_row["username"]
    target_blocked = user_row["is_blocked"]
    if request.method == 'POST':
        content = request.form.get('content')
        if not content:
            flash("메시지 내용을 입력하세요.", "warning")
            return redirect(url_for('chat', user_id=user_id))
        # 상대방이 차단된 경우 메시지 전송 불가
        if target_blocked:
            flash("해당 사용자는 차단된 상태입니다. 메시지를 보낼 수 없습니다.", "danger")
            return redirect(url_for('chat', user_id=user_id))
        # 메시지 DB 저장
        conn.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                     (current_user.id, user_id, content))
        conn.commit()
        return redirect(url_for('chat', user_id=user_id))
    # GET 요청: 기존 메시지 내역 불러오기
    cur = conn.execute("""
        SELECT m.id, m.sender_id, m.receiver_id, m.content, m.timestamp,
               s.username as sender_name, r.username as receiver_name
        FROM messages m 
        JOIN users s ON m.sender_id = s.id
        JOIN users r ON m.receiver_id = r.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp ASC
    """, (current_user.id, user_id, user_id, current_user.id))
    messages = cur.fetchall()
    return render_template('chat.html', messages=messages, other_username=target_username, other_id=user_id, target_blocked=target_blocked)

@app.route('/messages')
@login_required
def messages_list():
    """채팅 상대 목록 (메시지 함) 페이지"""
    conn = get_db()
    user_id = current_user.id
    # 현재 사용자가 참여한 모든 메시지에서 상대방 ID 추출
    cur1 = conn.execute("SELECT DISTINCT sender_id FROM messages WHERE receiver_id = ?", (user_id,))
    senders = [row["sender_id"] for row in cur1.fetchall()]
    cur2 = conn.execute("SELECT DISTINCT receiver_id FROM messages WHERE sender_id = ?", (user_id,))
    receivers = [row["receiver_id"] for row in cur2.fetchall()]
    others = set(senders + receivers)
    if user_id in others:
        others.discard(user_id)
    # 상대방들의 사용자 정보 조회
    others_list = []
    for oid in others:
        cur = conn.execute("SELECT id, username, is_blocked FROM users WHERE id = ?", (oid,))
        user = cur.fetchone()
        if user:
            others_list.append(user)
    return render_template('messages_list.html', others=others_list)

@app.route('/my-products')
@login_required
def my_products():
    conn = get_db()
    cur = conn.execute("""
        SELECT id, title, description, price
        FROM products
        WHERE seller_id = ?
        ORDER BY id DESC
    """, (current_user.id,))
    my_products = cur.fetchall()
    return render_template('my_products.html', products=my_products)

@app.route('/product/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    conn = get_db()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()

    if product is None:
        flash("상품이 존재하지 않습니다.", "danger")
        return redirect(url_for('index'))

    if product["seller_id"] != current_user.id:
        flash("자신이 등록한 상품만 수정할 수 있습니다.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get("title")
        description = request.form.get("description")
        price = request.form.get("price")

        if not title or not price:
            flash("상품명과 가격은 필수입니다.", "warning")
        else:
            conn.execute("UPDATE products SET title=?, description=?, price=? WHERE id=?",
                         (title, description, price, product_id))
            conn.commit()
            flash("상품이 수정되었습니다.", "success")
            return redirect(url_for('my_products'))

    return render_template('edit_product.html', product=product)

@app.route('/product/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    conn = get_db()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()

    if product is None:
        flash("삭제할 상품이 존재하지 않습니다.", "danger")
        return redirect(url_for('index'))

    if product["seller_id"] != current_user.id:
        flash("자신이 등록한 상품만 삭제할 수 있습니다.", "danger")
        return redirect(url_for('index'))

    conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for('my_products'))

@app.route('/report/product/<int:product_id>')
@login_required
def report_product(product_id):
    """상품 신고 처리"""
    conn = get_db()
    cur = conn.execute("SELECT seller_id, report_count, is_blocked FROM products WHERE id = ?", (product_id,))
    row = cur.fetchone()
    if row is None:
        flash("신고할 상품을 찾을 수 없습니다.", "warning")
        return redirect(url_for('index'))
    seller_id = row["seller_id"]
    # 자기 자신의 상품 신고 불가
    if seller_id == current_user.id:
        flash("자신의 상품은 신고할 수 없습니다.", "warning")
        return redirect(url_for('product_detail', product_id=product_id))
    # 이미 차단된 상품이면 신고 불필요
    if row["is_blocked"]:
        flash("이미 차단된 상품입니다.", "info")
        return redirect(url_for('product_detail', product_id=product_id))
    # 신고 횟수 증가
    new_count = row["report_count"] + 1
    is_block = 1 if new_count >= REPORT_THRESHOLD else 0
    conn.execute("UPDATE products SET report_count = ?, is_blocked = ? WHERE id = ?",
                 (new_count, is_block, product_id))
    conn.commit()
    if is_block:
        flash("상품이 누적 신고로 차단되었습니다.", "danger")
    else:
        flash("상품을 신고했습니다.", "info")
    return redirect(url_for('index'))

@app.route('/report/user/<int:user_id>')
@login_required
def report_user(user_id):
    """사용자 신고 처리"""
    conn = get_db()
    cur = conn.execute("SELECT username, is_admin, report_count, is_blocked FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        flash("신고할 사용자를 찾을 수 없습니다.", "warning")
        return redirect(url_for('index'))
    # 자기 자신이나 관리자는 신고 불가하도록
    if user_id == current_user.id:
        flash("자신을 신고할 수 없습니다.", "warning")
        return redirect(url_for('index'))
    if row["is_admin"]:
        flash("관리자는 신고할 수 없습니다.", "warning")
        return redirect(url_for('index'))
    # 이미 차단된 사용자면 신고 불필요
    if row["is_blocked"]:
        flash("이미 이용 정지된 사용자입니다.", "info")
        return redirect(url_for('index'))
    new_count = row["report_count"] + 1
    is_block = 1 if new_count >= REPORT_THRESHOLD else 0
    conn.execute("UPDATE users SET report_count = ?, is_blocked = ? WHERE id = ?",
                 (new_count, is_block, user_id))
    conn.commit()
    if is_block:
        flash("해당 사용자가 누적 신고로 차단되었습니다.", "danger")
    else:
        flash("사용자를 신고했습니다.", "info")
    return redirect(url_for('index'))

@app.route('/search')
def search():
    """상품 검색 기능"""
    query = request.args.get('q', '')
    query = query.strip()
    if query == '':
        flash("검색어를 입력해주세요.", "warning")
        return redirect(url_for('index'))
    conn = get_db()
    like_q = f"%{query}%"
    cur = conn.execute("""
        SELECT p.id, p.title, p.description, p.price, u.username as seller_name
        FROM products p JOIN users u ON p.seller_id = u.id
        WHERE p.is_blocked = 0 AND u.is_blocked = 0
          AND (p.title LIKE ? OR p.description LIKE ?)
        ORDER BY p.id DESC
    """, (like_q, like_q))
    results = cur.fetchall()
    return render_template('search.html', query=query, results=results)

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    """관리자 전용 신고 현황 페이지"""
    conn = get_db()
    # 신고된 사용자들 (report_count > 0)
    cur_u = conn.execute("SELECT id, username, report_count, is_blocked FROM users WHERE report_count > 0")
    users = cur_u.fetchall()
    # 신고된 상품들 (report_count > 0)
    cur_p = conn.execute("""
        SELECT p.id, p.title, p.report_count, p.is_blocked, u.username as seller_name 
        FROM products p JOIN users u ON p.seller_id = u.id
        WHERE p.report_count > 0
    """)
    products = cur_p.fetchall()
    return render_template('admin.html', users=users, products=products)

@app.route('/admin/unblock/user/<int:user_id>')
@login_required
@admin_required
def admin_unblock_user(user_id):
    """관리자 기능: 사용자 차단 해제"""
    conn = get_db()
    cur = conn.execute("SELECT username, is_blocked FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        if row["is_blocked"]:
            conn.execute("UPDATE users SET is_blocked = 0, report_count = 0 WHERE id = ?", (user_id,))
            conn.commit()
            flash(f"사용자 '{row['username']}'의 차단을 해제했습니다.", "success")
        else:
            flash("해당 사용자는 차단 상태가 아닙니다.", "info")
    else:
        flash("해당 사용자를 찾을 수 없습니다.", "warning")
    return redirect(url_for('admin_panel'))

@app.route('/admin/unblock/product/<int:product_id>')
@login_required
@admin_required
def admin_unblock_product(product_id):
    """관리자 기능: 상품 차단 해제"""
    conn = get_db()
    cur = conn.execute("SELECT title, is_blocked FROM products WHERE id = ?", (product_id,))
    row = cur.fetchone()
    if row:
        if row["is_blocked"]:
            conn.execute("UPDATE products SET is_blocked = 0, report_count = 0 WHERE id = ?", (product_id,))
            conn.commit()
            flash(f"상품 '{row['title']}'의 차단을 해제했습니다.", "success")
        else:
            flash("해당 상품은 차단 상태가 아닙니다.", "info")
    else:
        flash("해당 상품을 찾을 수 없습니다.", "warning")
    return redirect(url_for('admin_panel'))

# 상품 삭제
@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    conn = get_db()
    conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for('admin_panel'))

# 유저 삭제
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    flash("사용자가 삭제되었습니다.", "success")
    return redirect(url_for('admin_panel'))


# (옵션) Flask 애플리케이션 실행 - 개발용
if __name__ == '__main__':
    app.run(debug=True)
