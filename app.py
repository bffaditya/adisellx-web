from flask import Flask, render_template, request, redirect, url_for, session, flash, get_flashed_messages
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os # <-- Yeh zaroori hai
from functools import wraps # <== YEH LINE MISSING THI
from datetime import datetime # Date/Time ke liye
import razorpay
import hmac
import hashlib

# Bot code se refer reward liya
PRICE_CONFIG = {
    "refer_reward": 2,
    "refer_bonus": {"target": 15, "amount": 10}
}
# === YAHAN ADMIN USERNAME SET KAREIN ===
# Yeh username aapka Admin hoga
ADMIN_USERNAME = "admin"
VIP_DISCOUNT_PERCENT = 10 # VIPs ko 10% discount milega
# ===================================

# Flask app ko initialize karo
app = Flask(__name__)

# === RAZORPAY CONFIGURATION ===
# Apni Asli Keys Yahaan Daalein (Razorpay se)
RAZORPAY_KEY_ID = "rzp_test_RdYTWJOh0UQWSg"
RAZORPAY_KEY_SECRET = "oscp2KJ7vNtFWe5Lx3vu7hUt"
# Yeh aapne Step 2 mein banaya tha
RAZORPAY_WEBHOOK_SECRET = "oscp2KJ7vNtFWe5Lx3vu7hUt"

# Razorpay client ko setup karein
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
# ===============================

# === Configuration ===
app.config['SECRET_KEY'] = os.urandom(24)
DATABASE = 'users.db'

# === Database Functions ===
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # === 1. USERS (Sabse pehle) ===
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            wallet REAL DEFAULT 0,
            purchases INTEGER DEFAULT 0,
            referrals INTEGER DEFAULT 0,
            is_vip INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            device_fingerprint TEXT,
            referred_by_agent_id INTEGER DEFAULT NULL,
            FOREIGN KEY (referred_by_agent_id) REFERENCES agents (user_id)
        )
    ''')
    
    # === 2. PRODUCTS (Users ke baad) ===
    c.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            is_available INTEGER DEFAULT 1,
            is_deleted INTEGER DEFAULT 0
        )
    ''')
    
    # === 3. AGENTS (Users ke baad) ===
    c.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            user_id INTEGER PRIMARY KEY,
            commission_type TEXT DEFAULT 'CASH', -- CASH ya STARS
            total_cash_earned REAL DEFAULT 0,
            total_stars_earned INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # === 4. COMMISSION SETTINGS (Products ke baad) ===
    # (Sirf ek baar, sahi wala)
    c.execute('''
        CREATE TABLE IF NOT EXISTS commission_settings (
            product_id INTEGER PRIMARY KEY,
            cash_commission_type TEXT DEFAULT 'FIXED', 
            cash_commission_value REAL DEFAULT 0,
            star_commission_value INTEGER DEFAULT 0,
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')

    # === 5. ORDERS (Ab yeh sahi se banega) ===
    c.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            referrer_agent_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id),
            FOREIGN KEY (referrer_agent_id) REFERENCES agents (user_id)
        )
    ''')

    # === 6. REFERRALS (Users ke baad) ===
    c.execute('''
        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER NOT NULL,
            referred_id INTEGER NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (referrer_id) REFERENCES users (id),
            FOREIGN KEY (referred_id) REFERENCES users (id)
        )
    ''')

    # === 7. PUSH QUEUE ===
    c.execute('''
        CREATE TABLE IF NOT EXISTS push_queue (
            order_id INTEGER PRIMARY KEY, 
            user_id INTEGER, 
            user_display_name TEXT, 
            plan_name TEXT,
            total_target INTEGER, 
            current_progress INTEGER DEFAULT 0, 
            status TEXT DEFAULT 'WAITING',
            added_at INTEGER DEFAULT (strftime('%s', 'now')), 
            in_game_name TEXT, 
            in_game_uid TEXT,
            team_code TEXT, 
            expiry_time TEXT 
        )
    ''')
    
    # Products add karo (agar nahi hain toh)
    c.execute("SELECT COUNT(id) FROM products")
    if c.fetchone()[0] == 0:
        print("!!! Pehli baar products add kiye jaa rahe hain... !!!")
        paid_push_plans = [
            ("10 ⭐ Push", 50, "paid_push", "10 Stars Rank Push"),
            ("25 ⭐ Push", 120, "paid_push", "25 Stars Rank Push"),
            ("50 ⭐ Push", 220, "paid_push", "50 Stars Rank Push"),
            ("100 ⭐ Push", 400, "paid_push", "100 Stars Rank Push"),
            ("Grand Master", 1000, "paid_push", "Grand Master Rank Push"),
        ]
        c.executemany("INSERT INTO products (name, price, category, description) VALUES (?, ?, ?, ?)", paid_push_plans)
    
    conn.commit()
    conn.close()

    # === Helper Decorator (Check karta hai ki user admin hai ya nahi) ===
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("Aapke paas is page ka access nahi hai. Pehle Admin se Login karein.", "error")
            # Redirect to login page
            return redirect(url_for('login_page')) 
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    # === NAYA AGENT LINK LOGIC ===
    agent_ref_username = request.args.get('ref') # Link se ?ref=agent1 pakdo
    if agent_ref_username:
        conn = sqlite3.connect(DATABASE); c = conn.cursor()
        # Check karo ki yeh user ek valid agent hai
        c.execute("SELECT user_id FROM agents JOIN users ON agents.user_id = users.id WHERE users.username = ?", (agent_ref_username,))
        agent = c.fetchone()
        conn.close()
        if agent:
            # Agent ko session mein save karo taaki Register page isse pakad sake
            session['referrer_agent_id'] = agent[0]
            session['referrer_agent_username'] = agent_ref_username
            flash(f"Aap agent @{agent_ref_username} ke link se aaye hain!", "success")
    # ==========================
    return render_template('index.html')

@app.route('/paid-push')
def paid_push_page():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM products WHERE category = 'paid_push' AND is_available = 1")
    plans = c.fetchall()
    conn.close()
    return render_template('paid_push.html', plans=plans)

@app.route('/mobile-panel')
def mobile_panel_page():
    return render_template('mobile_panel.html')

@app.route('/buy-id')
def buy_id_page():
    return render_template('buy_id.html')

@app.route('/wallet')
def wallet_page():
    if 'user_id' not in session:
        flash("Wallet dekhne ke liye please login karein.", "error")
        return redirect(url_for('login_page'))
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    c = conn.cursor()
    c.execute("SELECT wallet, is_vip, purchases FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data is None:
        flash("User not found.", "error")
        return redirect(url_for('logout'))
    return render_template('wallet.html', user=user_data)

@app.route('/earn-money')
def earn_money_page():
    return render_template('earn_money.html')

@app.route('/refer-earn')
def refer_earn_page():
    if 'user_id' not in session:
        flash("Referral link dekhne ke liye please login karein.", "error")
        return redirect(url_for('login_page'))
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    c = conn.cursor()
    c.execute("SELECT referrals FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    referral_count = user_data['referrals'] if user_data else 0
    c.execute('''
        SELECT u.username, r.created_at
        FROM referrals r
        JOIN users u ON r.referred_id = u.id
        WHERE r.referrer_id = ?
        ORDER BY r.id DESC
    ''', (user_id,))
    referral_history = c.fetchall()
    conn.close()
    bonus_target = PRICE_CONFIG.get("refer_bonus", {}).get("target", 15)
    return render_template('refer_earn.html', 
                           referral_count=referral_count, 
                           bonus_target=bonus_target,
                           PRICE_CONFIG=PRICE_CONFIG,
                           referral_history=referral_history)

@app.route('/my-orders')
def my_orders_page():
    if 'user_id' not in session:
        flash("Orders dekhne ke liye please login karein.", "error")
        return redirect(url_for('login_page'))
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (session['user_id'],))
    orders = c.fetchall()
    conn.close()
    return render_template('my_orders.html', orders=orders)

@app.route('/offer')
def offer_page():
    return render_template('offer.html')

@app.route('/proofs')
def proofs_page():
    return render_template('proofs.html')

@app.route('/faq')
def faq_page():
    return render_template('faq.html')

@app.route('/support')
def support_page():
    return render_template('support.html')


# === "REGISTER" ROUTE (Aapka Device Fix wala code) ===
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    # User referral (e.g. ?ref=adi)
    referrer_username = request.args.get('ref')
    
    # Agent referral (session se)
    agent_id = session.get('referrer_agent_id')
    agent_username = session.get('referrer_agent_username')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        device_fingerprint = request.form.get('device_fingerprint', 'unknown')

        if password != confirm_password:
            flash("Passwords match nahi ho rahe!", "error"); return redirect(url_for('register_page'))

        password_hash = generate_password_hash(password)
        conn = sqlite3.connect(DATABASE); c = conn.cursor()
        
        try:
            # === NAYA LOGIC: Agent ID ko naye user ke saath save karo ===
            c.execute("INSERT INTO users (username, password_hash, device_fingerprint, referred_by_agent_id) VALUES (?, ?, ?, ?)", 
                      (username, password_hash, device_fingerprint, agent_id))
            new_user_id = c.lastrowid
            conn.commit()
            
            # Agent referral session clear karo
            if agent_id:
                session.pop('referrer_agent_id', None)
                session.pop('referrer_agent_username', None)

            # ... (Aapka purana USER referral logic yahaan (jaisa tha)) ...
            
            flash(f"Account ban gaya, {username}! Ab login karein.", "success")
            return redirect(url_for('login_page'))
            
        except sqlite3.IntegrityError as e:
            if 'UNIQUE constraint failed: users.username' in str(e):
                flash("Yeh username pehle se kisi ne le liya hai.", "error")
            else: flash(f"Ek database error aa gaya: {e}", "error")
            return redirect(url_for('register_page'))
        finally:
            conn.close()
            
    return render_template('register.html', referrer_username=referrer_username, agent_username=agent_username)


# === "LOGIN" ROUTE (ADMIN LOGIC KE SAATH UPDATE HUA) ===
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row 
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            # === YEH NAYA ADMIN CHECK HAI ===
            if user['username'] == ADMIN_USERNAME:
                session['is_admin'] = True
                flash(f"Welcome Admin, {username}!", "success")
            else:
                session['is_admin'] = False # Zaroori hai
                flash(f"Welcome back, {username}!", "success")
            # ==============================
            
            if 'next_url' in session:
                next_url = session.pop('next_url')
                return redirect(next_url)
            
            return redirect(url_for('home'))
        else:
            flash("Galat username ya password.", "error")
            return redirect(url_for('login_page'))
            
    return render_template('login.html')
# ========================================

# === "LOGOUT" ROUTE (ADMIN LOGIC KE SAATH UPDATE HUA) ===
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None) # Admin session bhi clear karo
    flash("Aap successfully logout ho gaye.", "success")
    return redirect(url_for('login_page'))
# ===============================================

# === "ADD FUNDS" ROUTE (LOGIN CHECK KE SAATH UPDATE HUA) ===
@app.route('/add-funds', methods=['GET', 'POST'])
def add_funds_page():
    if 'user_id' not in session:
        flash("Wallet mein paise add karne ke liye please login karein.", "error")
        session['next_url'] = url_for('add_funds_page') # Login ke baad yahin wapas aao
        return redirect(url_for('login_page'))
        
    if request.method == 'POST':
        try: amount = float(request.form['amount'])
        except ValueError:
            flash("Please ek sahi amount daalein (jaise 50 ya 100).", "error")
            return redirect(url_for('add_funds_page'))
        if amount < 50: 
            flash("Kam se kam ₹50 add kar sakte hain.", "error")
            return redirect(url_for('add_funds_page'))
        session['payment_amount'] = amount
        session['payment_order_id'] = f"ADI-WLT-{os.urandom(4).hex().upper()}"
        return redirect(url_for('add_funds_success'))
        
    return render_template('add_funds.html')
# ===============================================

@app.route('/add-funds/success')
def add_funds_success():
    if 'user_id' not in session or 'payment_amount' not in session:
        return redirect(url_for('home'))
    amount = session.pop('payment_amount', 0)
    order_id = session.pop('payment_order_id', 'N/A')
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("UPDATE users SET wallet = wallet + ? WHERE id = ?", (amount, user_id))
    c.execute("INSERT INTO orders (user_id, item_name, amount, status, created_at) VALUES (?, ?, ?, ?, ?)",
              (user_id, "💸 Wallet Top-Up", amount, "Delivered", datetime.now().strftime('%d %b %Y')))
    conn.commit()
    conn.close()
    flash(f"₹{amount} aapke wallet mein successfully add ho gaye!", "success")
    return render_template('add_funds_success.html', amount=amount, order_id=order_id)

# === "WITHDRAW" ROUTE (LOGIN CHECK KE SAATH UPDATE HUA) ===
@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw_page():
    if 'user_id' not in session:
        flash("Paise nikalne ke liye please login karein.", "error")
        session['next_url'] = url_for('withdraw_page') # Login ke baad yahin wapas aao
        return redirect(url_for('login_page'))
        
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT wallet FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    current_balance = user['wallet']
    min_withdraw = 50 
    
    if request.method == 'POST':
        try: amount = float(request.form['amount'])
        except ValueError:
            flash("Please ek sahi amount daalein (jaise 50 ya 100).", "error")
            conn.close(); return redirect(url_for('withdraw_page'))
        upi_details = request.form['upi_details']
        if amount < min_withdraw:
            flash(f"Kam se kam ₹{min_withdraw} nikal sakte hain.", "error")
            conn.close(); return redirect(url_for('withdraw_page'))
        if amount > current_balance:
            flash(f"Aapke paas itne paise (₹{current_balance}) nahi hain.", "error")
            conn.close(); return redirect(url_for('withdraw_page'))
        c.execute("UPDATE users SET wallet = wallet - ? WHERE id = ?", (amount, session['user_id']))
        c.execute("INSERT INTO orders (user_id, item_name, amount, status, created_at) VALUES (?, ?, ?, ?, ?)",
                  (session['user_id'], f"Withdrawal ({upi_details})", -amount, "Pending", datetime.now().strftime('%d %b %Y')))
        conn.commit()
        conn.close()
        flash(f"Aapki ₹{amount} ki withdrawal request bhej di gayi hai. Admin jald hi payment process karenge.", "success")
        return redirect(url_for('wallet_page'))
        
    conn.close()
    return render_template('withdraw.html', current_balance=current_balance)
# ===============================================

# === NAYA "CHECKOUT" ROUTE (POORA REPLACE KAREIN) ===
@app.route('/checkout/<int:product_id>')
def checkout_page(product_id):
    if 'user_id' not in session:
        flash("Checkout ke liye please login karein.", "error")
        session['next_url'] = url_for('checkout_page', product_id=product_id)
        return redirect(url_for('login_page'))
    
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()
    c.execute("SELECT * FROM products WHERE id = ?", (product_id,)); product = c.fetchone()
    c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)); user = c.fetchone()
    conn.close()
    
    if product is None:
        flash("Yeh product available nahi hai.", "error"); return redirect(url_for('home'))

    # === NAYA DISCOUNT LOGIC (Aapka "Plus Minus") ===
    original_price = product['price']
    discount_amount = 0
    
    # Check karo ki user VIP hai ya nahi
    if user['is_vip'] == 1:
        discount_amount = (original_price * VIP_DISCOUNT_PERCENT) / 100
        
    # (Future mein hum yahaan Promo Code ka discount bhi add kar sakte hain)
        
    final_price = original_price - discount_amount
    amount_in_paise = int(final_price * 100) # Razorpay ko final amount bhejo
    # ==========================

    try:
        # Razorpay ka order banayein
        razorpay_order_data = {
            "amount": amount_in_paise,
            "currency": "INR",
            "receipt": f"order_rcptid_{product_id}_{session['user_id']}_{int(datetime.now().timestamp())}",
            "notes": {
                "product_id": product_id,
                "user_id": session['user_id']
            }
        }
        razorpay_order = razorpay_client.order.create(data=razorpay_order_data)
        razorpay_order_id = razorpay_order['id']
    except Exception as e:
        flash(f"Payment server error: {e}", "error")
        return redirect(url_for('paid_push_page'))

    # Saari details HTML page ko bhejein
    return render_template('checkout.html', 
                           product=product, 
                           user=user,
                           original_price=original_price,
                           discount_amount=discount_amount,
                           final_price=final_price,
                           razorpay_order_id=razorpay_order_id,
                           razorpay_key_id=RAZORPAY_KEY_ID,
                           amount_in_paise=amount_in_paise)

# === "PAYMENT VERIFICATION" ROUTE (POORA REPLACE KAREIN) ===
# Yeh route Razorpay Webhook ke liye hai
@app.route('/payment-verification', methods=['POST'])
def payment_verification():
    
    # Step 1: Webhook signature ko verify karo
    webhook_body = request.data
    webhook_signature = request.headers.get('X-Razorpay-Signature')
    
    if not webhook_signature:
        return 'OK', 200 # Agar signature nahi hai toh ignore karo

    try:
        generated_signature = hmac.new(
            RAZORPAY_WEBHOOK_SECRET.encode('utf-8'),
            webhook_body,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(generated_signature, webhook_signature):
            print("Webhook Signature Mismatch")
            return 'Invalid signature', 400
            
    except Exception as e:
        print(f"Webhook Signature Error: {e}")
        return 'Error', 400

    # Step 2: Payment data ko JSON se nikalo
    try:
        payment_data = request.json
        if payment_data['event'] != 'payment.captured':
            return 'OK' # Hum sirf captured payments mein interested hain

        payment = payment_data['payload']['payment']['entity']
        order_notes = payment['notes']
        
        user_id = int(order_notes['user_id'])
        product_id = int(order_notes['product_id'])

    except Exception as e:
        print(f"Webhook JSON read error: {e}")
        return 'Bad request', 400

    # === Step 3: Order ko Database mein Save Karo (Wahi logic) ===
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()
    
    try:
        c.execute("SELECT * FROM products WHERE id = ?", (product_id,)); product = c.fetchone()
        c.execute("SELECT referred_by_agent_id FROM users WHERE id = ?", (user_id,)); user_data = c.fetchone()
        agent_id = user_data['referred_by_agent_id'] if user_data and user_data['referred_by_agent_id'] else None

        # Order ko "Pending" status mein save karo
        c.execute("INSERT INTO orders (user_id, product_id, item_name, amount, status, created_at, referrer_agent_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (user_id, product_id, product['name'], product['price'], "Pending", datetime.now().strftime('%d %b %Y'), agent_id))
        new_order_id = c.lastrowid
        
        c.execute("UPDATE users SET purchases = purchases + 1 WHERE id = ?", (user_id,))
        
        # === Step 4: Order ko Auto-Approve/Move to Push Karo ===
        plan_name = product['name']
        if "Push" in plan_name:
            total_target = int(plan_name.split('⭐')[0].strip())
            c.execute("UPDATE orders SET status = 'Delivered' WHERE id = ?", (new_order_id,))
            c.execute("SELECT username FROM users WHERE id = ?", (user_id,)); user_row = c.fetchone()
            username = user_row['username'] if user_row else "Unknown User"
            c.execute('''INSERT INTO push_queue (order_id, user_id, user_display_name, plan_name, total_target, status) VALUES (?, ?, ?, ?, ?, 'WAITING')''', 
                      (new_order_id, user_id, username, plan_name, total_target))

            # === COMMISSION LOGIC ===
            if agent_id:
                c.execute("SELECT commission_type FROM agents WHERE user_id = ?", (agent_id,)); agent = c.fetchone()
                c.execute("SELECT * FROM commission_settings WHERE product_id = ?", (product_id,)); settings = c.fetchone()
                if agent and settings:
                    if agent['commission_type'] == 'CASH':
                        cash_earned = settings['cash_commission_value']
                        if cash_earned > 0:
                            c.execute("UPDATE users SET wallet = wallet + ? WHERE id = ?", (cash_earned, agent_id))
                            c.execute("UPDATE agents SET total_cash_earned = total_cash_earned + ? WHERE user_id = ?", (cash_earned, agent_id))
                    elif agent['commission_type'] == 'STARS':
                        stars_earned = settings['star_commission_value']
                        if stars_earned > 0: c.execute("UPDATE agents SET total_stars_earned = total_stars_earned + ? WHERE user_id = ?", (stars_earned, agent_id))
        else:
            c.execute("UPDATE orders SET status = 'Delivered' WHERE id = ?", (new_order_id,))
        
        conn.commit()
    except Exception as e:
        print(f"DATABASE SAVE ERROR: {e}")
    finally:
        conn.close()

    # Razorpay ko "OK" message bhejo
    return 'OK', 200

# === NAYA ADMIN ACTION LOGIC YAHAN ADD KAREIN ===

# Helper function to decide if item is a product purchase (not a wallet action)
def product_is_purchase(item_name):
    return not ("Top-Up" in item_name or "Withdrawal" in item_name)


# Route 22: Approve Order
@app.route('/admin/approve/<int:order_id>')
def admin_approve_order(order_id):
    if not session.get('is_admin'):
        flash("Unauthorized access.", "error")
        return redirect(url_for('home'))

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT user_id, item_name, amount, status FROM orders WHERE id = ?", (order_id,))
    order = c.fetchone()

    if not order or order['status'] != 'Pending':
        conn.close()
        flash("Order ya toh mil nahi raha ya pehle se processed hai.", "warning")
        return redirect(url_for('admin_manage_orders'))

    user_id = order['user_id']
    item_name = order['item_name']
    amount = order['amount']
    
    try:
        # Status ko 'Delivered' ya 'Completed' mein badalna
        if "Withdrawal" in item_name:
            # Withdrawal request hai, isse 'Delivered' (Paid) mark kar do
            c.execute("UPDATE orders SET status = 'Delivered' WHERE id = ?", (order_id,))
            flash_msg = f"💸 Withdrawal #{order_id} approved. (User's balance already deducted)."
        else:
            # Product/Paid Push order hai
            c.execute("UPDATE orders SET status = 'Delivered' WHERE id = ?", (order_id,))
            
            # Agar Top-Up tha (Top-Up Delivered means Admin ne pay kar diya)
            if "Top-Up" in item_name:
                 # NOTE: Wallet Top-up logic abhi ke liye simple hai. Real payment gateway hone par yahan logic badlega.
                 pass
            
            # Agar product purchase hai, toh purchase count badhao (VIP ke liye)
            if product_is_purchase(item_name):
                 # Humne yeh logic pehle hi 'pay_page' mein daal diya tha, but yahaan double check karte hain
                 # c.execute("UPDATE users SET purchases = purchases + 1 WHERE id = ?", (user_id,))
                 pass 
            
            flash_msg = f"✅ Order #{order_id} ({item_name}) approved & marked as delivered."

        conn.commit()
        flash(flash_msg, "success")
        return redirect(url_for('admin_manage_orders'))

    except Exception as e:
        flash(f"Error approving order: {e}", "error")
        return redirect(url_for('admin_manage_orders'))
    finally:
        conn.close()


# Route 23: Reject Order
@app.route('/admin/reject/<int:order_id>')
def admin_reject_order(order_id):
    if not session.get('is_admin'):
        flash("Unauthorized access.", "error")
        return redirect(url_for('home'))

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT user_id, item_name, amount, status FROM orders WHERE id = ?", (order_id,))
    order = c.fetchone()

    if not order or order['status'] != 'Pending':
        conn.close()
        flash("Order ya toh mil nahi raha ya pehle se processed hai.", "warning")
        return redirect(url_for('admin_manage_orders'))

    user_id = order['user_id']
    item_name = order['item_name']
    amount = order['amount']
    
    try:
        c.execute("UPDATE orders SET status = 'Rejected' WHERE id = ?", (order_id,))
        
        # Agar withdrawal request reject ho rahi hai, toh paise wapas user ke wallet mein daalo
        if "Withdrawal" in item_name:
            c.execute("UPDATE users SET wallet = wallet + ? WHERE id = ?", (-amount, user_id)) 
            flash_msg = f"❌ Withdrawal #{order_id} rejected. Funds returned to user wallet."
        else:
            flash_msg = f"❌ Order #{order_id} ({item_name}) rejected."
        
        conn.commit()
        flash(flash_msg, "success")
        return redirect(url_for('admin_manage_orders'))

    except Exception as e:
        flash(f"Error rejecting order: {e}", "error")
        return redirect(url_for('admin_manage_orders'))
    finally:
        conn.close()



# === NAYA ADMIN PANEL ROUTE ===
@app.route('/admin')
def admin_dashboard():
    # Check karo ki user admin hai ya nahi
    if not session.get('is_admin'):
        flash("Aapke paas is page ka access nahi hai.", "error")
        return redirect(url_for('home'))
        
    # Abhi ke liye bas dashboard page dikhao
    return render_template('admin/dashboard.html')
# ============================

# === NAYA BLOCK YAHAN ADD KAREIN (APPROVE/REJECT KE BAAD) ===

# Route 24: Manage Products Page (/admin/products)
@app.route('/admin/products')
def admin_manage_products():
    if not session.get('is_admin'):
        flash("Unauthorized access.", "error")
        return redirect(url_for('home'))

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Saare products categories ke saath nikalo
    c.execute("SELECT * FROM products ORDER BY category, id")
    products = c.fetchall()
    conn.close()
    
    # products ko HTML page par bhej do
    return render_template('admin/manage_products.html', products=products) # <-- Yeh line already sahi hai, agar aapne file templates/admin/ ke andar rakhi hai.

# Route 25: Update All Prices (Form POST)
@app.route('/admin/products/update_all', methods=['POST'])
def admin_update_all_prices():
    if not session.get('is_admin'):
        return redirect(url_for('home'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    products_updated = 0
    
    # Request form data ko loop karte hain
    for key, value in request.form.items():
        if key.startswith('price_'):
            try:
                product_id = int(key.split('_')[1])
                new_price = float(value)
                
                # Database mein price update karo
                c.execute("UPDATE products SET price = ? WHERE id = ?", (new_price, product_id))
                products_updated += 1
            except (ValueError, IndexError):
                # Agar koi price galat daalta hai
                flash("Ek price galat format mein tha aur update nahi kiya gaya.", "warning")
                conn.rollback() # Agar koi galti ho to sab changes undo kar do
                return redirect(url_for('admin_manage_products'))

    conn.commit()
    conn.close()
    flash(f"✅ {products_updated} products ki prices safaltapoorvak update ho gayi.", "success")
    return redirect(url_for('admin_manage_products'))


# Route 26: Toggle Availability (Link GET)
@app.route('/admin/products/toggle_availability/<int:product_id>')
def admin_toggle_availability(product_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Status ko toggle (ulta) karo
    c.execute("UPDATE products SET is_available = 1 - is_available WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    
    flash("✅ Product ki availability status badal di gayi.", "success")
    return redirect(url_for('admin_manage_products'))


# Route 27: Delete Product (Link GET)
@app.route('/admin/products/delete/<int:product_id>')
def admin_delete_product(product_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    
    flash("🗑️ Product ko database se hata diya gaya.", "success")
    return redirect(url_for('admin_manage_products'))

# === NAYA ADMIN ROUTE YAHAN ADD KAREIN ===
# === Route 21: Manage Orders Page (/admin/orders) ===
@app.route('/admin/orders')
def admin_manage_orders():
    if not session.get('is_admin'):
        flash("Aapke paas is page ka access nahi hai.", "error")
        return redirect(url_for('home'))

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Sirf 'Pending' orders nikalo
    c.execute('''
        SELECT o.id, u.username, o.item_name, o.amount, o.created_at
        FROM orders o
        JOIN users u ON o.user_id = u.id
        WHERE o.status = 'Pending'
        ORDER BY o.id ASC
    ''')
    pending_orders = c.fetchall()
    conn.close()

    # orders ko HTML page par bhej do
    return render_template('admin/admin_orders.html', pending_orders=pending_orders) # <-- admin/ folder ke andar dhoondhega
# ===============================================

# ==================================================================
# ================= PUSH CONTROL CENTER (PCC) ROUTES ================
# ==================================================================

# Route 28: Push Control Center Page (MAIN VIEW)
@app.route('/admin/push-control')
@admin_required
def admin_push_control():
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()
    
    # 1. Naya: In-Progress Players (Jinko TeamCode Bhej Diya Hai)
    c.execute("SELECT p.*, u.username FROM push_queue p LEFT JOIN users u ON p.user_id = u.id WHERE p.status = 'IN_PROGRESS' ORDER BY p.added_at ASC")
    inprogress_players = c.fetchall()

    # 2. Lobby (Active) Players (Jo TeamCode ka Wait Kar Rahe Hain)
    c.execute("SELECT p.*, u.username FROM push_queue p LEFT JOIN users u ON p.user_id = u.id WHERE p.status = 'IN_LOBBY' ORDER BY p.added_at ASC")
    lobby_players = c.fetchall()

    # 3. Waiting/Paused Players
    c.execute("SELECT p.*, u.username FROM push_queue p LEFT JOIN users u ON p.user_id = u.id WHERE p.status IN ('WAITING', 'PAUSED') ORDER BY p.added_at ASC")
    waiting_players = c.fetchall()
    
    conn.close()
    
    return render_template('admin/push_control.html', 
                           inprogress_players=inprogress_players, # Naya data
                           lobby_players=lobby_players, 
                           waiting_players=waiting_players)

# Route 29: Move Order to Push Queue (COMMISSION LOGIC KE SAATH)
@app.route('/admin/move_to_push/<int:order_id>')
@admin_required
def admin_move_to_push(order_id):
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()
    
    # Order details nikalo (jismein agent ID bhi hai)
    c.execute("SELECT user_id, product_id, item_name, amount, referrer_agent_id FROM orders WHERE id = ? AND status = 'Pending'", (order_id,))
    order = c.fetchone()
    
    if not order:
        c.execute("SELECT order_id FROM push_queue WHERE order_id = ?", (order_id,))
        if c.fetchone(): flash("⚠️ Order pehle hi Push Queue mein hai.", "warning"); conn.close(); return redirect(url_for('admin_push_control'))
        flash("❌ Order Pending status mein nahi mila.", "error"); conn.close(); return redirect(url_for('admin_manage_orders'))

    plan_name = order['item_name']
    product_id = order['product_id']
    referrer_agent_id = order['referrer_agent_id']
    
    try: total_target = int(plan_name.split('⭐')[0].strip())
    except Exception: flash("❌ Push Queue ke liye nahi hai.", "warning"); conn.close(); return redirect(url_for('admin_manage_orders'))
    
    # 1. Order ko Delivered mark karo
    c.execute("UPDATE orders SET status = 'Delivered' WHERE id = ?", (order_id,))
    
    # 2. Push Queue mein add karo
    c.execute("SELECT username FROM users WHERE id = ?", (order['user_id'],)); user_row = c.fetchone()
    username = user_row['username'] if user_row else "Unknown User"
    c.execute('''INSERT INTO push_queue (order_id, user_id, user_display_name, plan_name, total_target, status) VALUES (?, ?, ?, ?, ?, 'WAITING')''', 
              (order_id, order['user_id'], username, plan_name, total_target))

    # === 3. NAYA COMMISSION LOGIC ===
    commission_message = ""
    if referrer_agent_id:
        # Agent ka type (CASH/STARS) nikalo
        c.execute("SELECT commission_type FROM agents WHERE user_id = ?", (referrer_agent_id,))
        agent = c.fetchone()
        
        # Commission settings nikalo
        c.execute("SELECT * FROM commission_settings WHERE product_id = ?", (product_id,))
        settings = c.fetchone()
        
        if agent and settings:
            if agent['commission_type'] == 'CASH':
                cash_earned = settings['cash_commission_value']
                if cash_earned > 0:
                    c.execute("UPDATE users SET wallet = wallet + ? WHERE id = ?", (cash_earned, referrer_agent_id))
                    c.execute("UPDATE agents SET total_cash_earned = total_cash_earned + ? WHERE user_id = ?", (cash_earned, referrer_agent_id))
                    commission_message = f" (Agent ko ₹{cash_earned} commission mil gaya)"
            
            elif agent['commission_type'] == 'STARS':
                stars_earned = settings['star_commission_value']
                if stars_earned > 0:
                    c.execute("UPDATE agents SET total_stars_earned = total_stars_earned + ? WHERE user_id = ?", (stars_earned, referrer_agent_id))
                    commission_message = f" (Agent ko {stars_earned}⭐ commission mil gaya)"
    # ==============================
    
    conn.commit(); conn.close()
    flash(f"✅ Order #{order_id} Push Queue mein add ho gaya." + commission_message, "success")
    return redirect(url_for('admin_push_control'))

# Route 30: Move to Lobby (Waiting se Active)
@app.route('/admin/push/add_lobby/<int:order_id>')
@admin_required
def admin_push_add_lobby(order_id):
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("UPDATE push_queue SET status = 'IN_LOBBY' WHERE order_id = ?", (order_id,))
    conn.commit(); conn.close(); flash(f"✅ Push #{order_id} Lobby में add हो गया।", "success"); return redirect(url_for('admin_push_control'))

# Route 31: Remove from Lobby (Wapas Waiting mein)
@app.route('/admin/push/remove_lobby/<int:order_id>')
@admin_required
def admin_push_remove_lobby(order_id):
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("UPDATE push_queue SET status = 'WAITING' WHERE order_id = ?", (order_id,))
    conn.commit(); conn.close(); flash(f"↩️ Push #{order_id} Lobby से हटा कर Waiting में भेज दिया गया।", "success"); return redirect(url_for('admin_push_control'))

# Route 32: Mark Push Completed
@app.route('/admin/push/complete/<int:order_id>')
@admin_required
def admin_push_complete(order_id):
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("UPDATE push_queue SET status = 'COMPLETED' WHERE order_id = ?", (order_id,))
    conn.commit(); conn.close(); flash(f"🎉 Push #{order_id} Completed mark कर दिया गया।", "success"); return redirect(url_for('admin_push_control'))

# Route 33: IGN/UID Update Form Page
@app.route('/admin/push/update_info/<int:order_id>')
@admin_required
def admin_push_update_info_form(order_id):
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()
    c.execute("SELECT user_display_name, in_game_name, in_game_uid FROM push_queue WHERE order_id = ?", (order_id,))
    player = c.fetchone(); conn.close()
    if not player: flash("Player ki entry nahi mili.", "error"); return redirect(url_for('admin_push_control'))
    return render_template('admin/update_push_info.html', player=player, order_id=order_id)


# Route 34: IGN/UID Data Save Karne ka Logic
@app.route('/admin/push/save_info/<int:order_id>', methods=['POST'])
@admin_required
def admin_push_save_info(order_id):
    ign = request.form['ign']; uid = request.form['uid']
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("UPDATE push_queue SET in_game_name = ?, in_game_uid = ? WHERE order_id = ?", (ign, uid, order_id))
    conn.commit(); conn.close()
    flash(f"✅ Player #{order_id} ki IGN/UID ({ign} / {uid}) update ho gayi hai.", "success")
    return redirect(url_for('admin_push_control'))


# Route 37: TeamCode Form Page (Admin)
@app.route('/admin/push/send_teamcode_form')
@admin_required
def admin_push_teamcode_form():
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("SELECT COUNT(order_id) FROM push_queue WHERE status = 'IN_LOBBY'")
    lobby_count = c.fetchone()[0]; conn.close()
    
    if lobby_count == 0:
        flash("⚠️ Lobby khaali hai. TeamCode bhej nahi sakte.", "warning")
        return redirect(url_for('admin_push_control'))

    # Nayi file ko render karo
    return render_template('admin/send_teamcode.html')


# Route 38: TeamCode Send Logic (POST request)
@app.route('/admin/push/send_teamcode', methods=['POST'])
@admin_required
def admin_push_send_teamcode():
    team_code = request.form['team_code'].strip()
    
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("SELECT order_id FROM push_queue WHERE status = 'IN_LOBBY'")
    lobby_players = c.fetchall() # Saare lobby players ko nikalo
    lobby_count = len(lobby_players)

    if not team_code:
        flash("❌ TeamCode khaali nahi ho sakta.", "error")
    elif lobby_count == 0:
        flash("⚠️ Lobby khaali hai. TeamCode nahi bheja gaya.", "warning")
    else:
        # === YEH NAYA LOGIC HAI ===
        # Lobby ke sabhi players ko 'IN_PROGRESS' mein daalo
        for player in lobby_players:
            order_id = player[0]
            # Yahaan hum TeamCode ko database mein save kar rahe hain
            c.execute("UPDATE push_queue SET status = 'IN_PROGRESS', team_code = ? WHERE order_id = ?", (team_code, order_id))
        
        conn.commit()
        # ==========================
        flash(f"✅ TeamCode '{team_code}' Lobby ke {lobby_count} players ko bhej diya gaya hai aur 'In Progress' mein move kar diya gaya hai।", "success")
        
    conn.close()
    return redirect(url_for('admin_push_control'))

# === YEH DO MISSING FUNCTIONS HAIN, INHE ADD KAREIN ===

# Route 35: Progress Update Form Page
@app.route('/admin/push/update_progress_form/<int:order_id>')
@admin_required
def admin_push_update_progress_form(order_id):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT user_display_name, current_progress, total_target FROM push_queue WHERE order_id = ?", (order_id,))
    player = c.fetchone()
    conn.close()
    
    if not player:
        flash("Player ki entry nahi mili.", "error")
        return redirect(url_for('admin_push_control'))
        
    return render_template('admin/update_push_progress.html', player=player, order_id=order_id)


# Route 36: Progress Update Data Save Karne ka Logic
@app.route('/admin/push/save_progress/<int:order_id>', methods=['POST'])
@admin_required
def admin_push_save_progress(order_id):
    try:
        new_progress = int(request.form['progress'])
    except ValueError:
        flash("❌ Progress number mein hona chahiye.", "error")
        return redirect(url_for('admin_push_control'))
        
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Database mein progress update karo
    c.execute("UPDATE push_queue SET current_progress = ? WHERE order_id = ?", (new_progress, order_id))
    conn.commit()
    conn.close()
    
    flash(f"✅ Player #{order_id} ki progress update ho gayi hai ({new_progress} stars).", "success")
    return redirect(url_for('admin_push_control'))

# === NAYA LOGIC: SET OFFLINE TIME (YEH MISSING THA) ===

# Route 39: Set Offline Time Form
@app.route('/admin/push/set_offline_form')
@admin_required
def admin_push_set_offline_form():
    return render_template('admin/set_offline.html')

# Route 40: Notify Offline Logic
@app.route('/admin/push/notify_offline', methods=['POST'])
@admin_required
def admin_push_notify_offline():
    offline_time = request.form['offline_time']
    
    # Yahaan hum waiting/paused users ko notify karte hain (Future mein)
    
    flash(f"🌙 Offline Time '{offline_time}' sabhi waiting users ko notify kar diya gaya hai।", "success")
    return redirect(url_for('admin_push_control'))

# === NAYA LOGIC: DOBARA TEAMCODE BHEJNE KE LIYE ===

# Route 40: (Single Player) TeamCode Form Dikhane ke liye
@app.route('/admin/push/resend_teamcode_form/<int:order_id>')
@admin_required
def admin_push_resend_teamcode_form(order_id):
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()
    c.execute("SELECT user_display_name, in_game_name, in_game_uid, team_code FROM push_queue WHERE order_id = ?", (order_id,))
    player = c.fetchone(); conn.close()
    
    if not player:
        flash("Player ki entry nahi mili.", "error")
        return redirect(url_for('admin_push_control'))
        
    return render_template('admin/resend_teamcode.html', player=player, order_id=order_id)


# Route 41: (Single Player) TeamCode Save Karne ka Logic
@app.route('/admin/push/resend_teamcode/<int:order_id>', methods=['POST'])
@admin_required
def admin_push_resend_teamcode(order_id):
    team_code = request.form['team_code'].strip()
    
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    
    # Database mein NAYA team_code update karo (Status 'IN_PROGRESS' hi rahega)
    c.execute("UPDATE push_queue SET team_code = ? WHERE order_id = ?", (team_code, order_id))
    conn.commit()
    conn.close()
    
    flash(f"✅ Player #{order_id} ko NAYA TeamCode ({team_code}) bhej diya gaya hai.", "success")
    return redirect(url_for('admin_push_control'))

# === NAYE BUTTONS KA LOGIC ===

# Route 42: Player ko 'Paused' karna
@app.route('/admin/push/pause/<int:order_id>')
@admin_required
def admin_push_pause(order_id):
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("UPDATE push_queue SET status = 'PAUSED' WHERE order_id = ?", (order_id,))
    conn.commit(); conn.close()
    flash(f"⏸️ Push #{order_id} 'Paused' set kar diya gaya hai.", "success")
    return redirect(url_for('admin_push_control'))

# Route 43: Player ko 'In Progress' se wapas 'Lobby' mein laana
@app.route('/admin/push/return_to_lobby/<int:order_id>')
@admin_required
def admin_push_return_to_lobby(order_id):
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("UPDATE push_queue SET status = 'IN_LOBBY', team_code = NULL WHERE order_id = ?", (order_id,))
    conn.commit(); conn.close()
    flash(f"🔄 Push #{order_id} wapas Lobby mein aa gaya hai. Naya TeamCode bhej sakte hain.", "success")
    return redirect(url_for('admin_push_control'))

# ==================================================================
# ======================= 5. AGENT ROUTES ==========================
# ==================================================================

# Route 44: Manage Agents Page (MAIN VIEW)
@app.route('/admin/agents')
@admin_required
def admin_manage_agents():
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()
    
    # Saare agents ko unke user details ke saath nikalo
    c.execute('''
        SELECT a.*, u.username 
        FROM agents a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
    ''')
    agents = c.fetchall()
    
    # Sabhi users ko nikalo jo agent nahi hain (Add karne ke liye)
    c.execute('''
        SELECT u.id, u.username 
        FROM users u
        WHERE u.id NOT IN (SELECT user_id FROM agents)
        ORDER BY u.username ASC
    ''')
    potential_agents = c.fetchall()
    
    conn.close()
    
    return render_template('admin/manage_agents.html', 
                           agents=agents, 
                           potential_agents=potential_agents)

# Route 45: Naya Agent Add Karna
@app.route('/admin/agents/add', methods=['POST'])
@admin_required
def admin_add_agent():
    user_id = request.form['user_id']
    commission_type = request.form['commission_type']

    if not user_id:
        flash("❌ User select karna zaroori hai.", "error")
        return redirect(url_for('admin_manage_agents'))

    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    try:
        c.execute("INSERT INTO agents (user_id, commission_type) VALUES (?, ?)", (user_id, commission_type))
        conn.commit()
        flash(f"✅ Naya agent (Type: {commission_type}) safaltapoorvak add ho gaya.", "success")
    except sqlite3.IntegrityError:
        flash(f"⚠️ Yeh user pehle se hi agent hai.", "warning")
    except Exception as e:
        flash(f"❌ Error: {e}", "error")
    finally:
        conn.close()
        
    return redirect(url_for('admin_manage_agents'))

# Route 46: Agent ko Delete Karna
@app.route('/admin/agents/delete/<int:user_id>')
@admin_required
def admin_delete_agent(user_id):
    conn = sqlite3.connect(DATABASE); c = conn.cursor()
    c.execute("DELETE FROM agents WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash(f"🗑️ Agent (User ID: {user_id}) ko hata diya gaya hai.", "success")
    return redirect(url_for('admin_manage_agents'))

# === NAYA COMMISSION LOGIC ===

# Route 47: Commission Settings Page (MAIN VIEW)
@app.route('/admin/commission-settings', methods=['GET', 'POST'])
@admin_required
def admin_commission_settings():
    conn = sqlite3.connect(DATABASE); conn.row_factory = sqlite3.Row; c = conn.cursor()

    if request.method == 'POST':
        # Form se saara data save karo
        try:
            for key, value in request.form.items():
                if key.startswith('cash_comm_'):
                    product_id = key.split('_')[-1]
                    cash_value = float(request.form.get(f'cash_comm_{product_id}', 0))
                    star_value = int(request.form.get(f'star_comm_{product_id}', 0))
                    
                    # INSERT OR REPLACE ka matlab hai: Agar product_id pehle se hai toh UPDATE karo, warna naya INSERT karo
                    c.execute('''
                        INSERT OR REPLACE INTO commission_settings 
                        (product_id, cash_commission_type, cash_commission_value, star_commission_value)
                        VALUES (?, 'FIXED', ?, ?)
                    ''', (product_id, cash_value, star_value))
            
            conn.commit()
            flash("✅ Commission settings safaltapoorvak save ho gayi.", "success")
        except Exception as e:
            flash(f"❌ Error saving settings: {e}", "error")
        finally:
            conn.close()
        
        return redirect(url_for('admin_commission_settings'))

    # 'GET' request (Page load karne ke liye)
    # Saare products nikalo (jo delete nahi hue hain)
    c.execute("SELECT id, name, price, category FROM products WHERE is_deleted = 0 ORDER BY category, id")
    products = c.fetchall()
    
    # Har product ki current commission setting nikalo
    c.execute("SELECT * FROM commission_settings")
    # Commission settings ko ek dictionary mein daalo taaki HTML mein use karna aasaan ho
    settings = {row['product_id']: row for row in c.fetchall()}
    
    conn.close()
    
    return render_template('admin/commission_settings.html', products=products, settings=settings)

# === Server ko Run Karne ke liye ===
if __name__ == '__main__':
    print("!!! DATABASE KO INITIALIZE KIYA JAA RAHA HAI... !!!")
    init_db() 
    app.run(debug=True, port=5000)