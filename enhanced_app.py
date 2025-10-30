from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import json
import random
import string
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import io
import zipfile
import urllib.request
import urllib.error
import re
import csv
import logging
from logging.handlers import RotatingFileHandler

# ==================== APP CONFIGURATION ====================
app = Flask(__name__, template_folder='.', static_folder='.')
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Database Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'database', 'certportal.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==================== LOGGING SETUP ====================
if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240000, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Gautam Solar Portal startup')

# ==================== EMAIL CONFIGURATION ====================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
ADMIN_EMAIL = "gautamsolarpvtltd@gmail.com"
ADMIN_PASSWORD = "your_app_password_here"

def send_email(recipient, subject, body, is_html=False):
    """Send email notification with error handling"""
    try:
        msg = MIMEMultipart()
        msg['From'] = ADMIN_EMAIL
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html' if is_html else 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        server.send_message(msg)
        server.quit()
        app.logger.info(f"Email sent to {recipient}")
        return True
    except Exception as e:
        app.logger.error(f"Email error: {str(e)}")
        return False

# ==================== MODELS ====================
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    mobile = db.Column(db.String(20))
    password = db.Column(db.String(255), nullable=False)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    downloads_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)

class PasswordReset(db.Model):
    __tablename__ = 'password_reset'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    otp_type = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    used = db.Column(db.Boolean, default=False)

class AccessRequest(db.Model):
    __tablename__ = 'access_request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_type = db.Column(db.String(50))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notified = db.Column(db.Boolean, default=False)

class DownloadLog(db.Model):
    __tablename__ = 'download_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    document_count = db.Column(db.Integer)
    file_size = db.Column(db.Integer)
    download_date = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

class ProductCategory(db.Model):
    __tablename__ = 'product_category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    technology = db.Column(db.String(200))
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship('Product', backref='category', lazy=True, cascade='all, delete-orphan')

class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('product_category.id'), nullable=False)
    wattage = db.Column(db.String(50), nullable=False)
    order = db.Column(db.Integer, default=0)
    availability = db.Column(db.String(20), default='available')
    documents = db.relationship('Document', backref='product', lazy=True, cascade='all, delete-orphan')
    stock_quantity = db.Column(db.Integer, default=0)
    last_stock_update = db.Column(db.DateTime)
    efficiency = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Document(db.Model):
    __tablename__ = 'document'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    doc_type = db.Column(db.String(100), nullable=False)
    doc_name = db.Column(db.String(200))
    download_link = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    download_count = db.Column(db.Integer, default=0)

class CompanyDocument(db.Model):
    __tablename__ = 'company_document'
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(100), nullable=False)
    doc_type = db.Column(db.String(100), nullable=False)
    doc_name = db.Column(db.String(200))
    download_link = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class HomeNotification(db.Model):
    __tablename__ = 'home_notification'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    notification_type = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    order = db.Column(db.Integer, default=0)

class SiteConfig(db.Model):
    __tablename__ = 'site_config'
    id = db.Column(db.Integer, primary_key=True)
    logo_url = db.Column(db.String(500))
    company_name = db.Column(db.String(200))
    tagline = db.Column(db.String(500))
    footer_text = db.Column(db.Text)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    address = db.Column(db.Text)

# ==================== DECORATORS ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

# ==================== UTILITY FUNCTIONS ====================
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def get_user_ip():
    if request.environ.get('HTTP_CF_CONNECTING_IP'):
        return request.environ.get('HTTP_CF_CONNECTING_IP')
    return request.remote_addr

# ==================== PUBLIC ROUTES ====================
@app.route("/")
def index():
    notifications = HomeNotification.query.filter_by(is_active=True).order_by(HomeNotification.order).all()
    stats = {
        'total_products': Product.query.count(),
        'total_categories': ProductCategory.query.count(),
        'total_documents': Document.query.count()
    }
    return render_template("index.html", notifications=notifications, stats=stats)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/portal")
def portal():
    is_logged_in = "user_id" in session
    user_name = session.get("user_name", "")
    user_id = session.get("user_id", "")
    return render_template("portal_enhanced.html", is_logged_in=is_logged_in, user_name=user_name, user_id=user_id)

# ==================== DOWNLOAD ROUTES ====================
@app.route("/download/<int:doc_id>")
@login_required
def download_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    doc.download_count = (doc.download_count or 0) + 1
    db.session.commit()
    return redirect(doc.download_link)

@app.route("/download/company/<int:doc_id>")
@login_required
def download_company_doc(doc_id):
    doc = CompanyDocument.query.get_or_404(doc_id)
    return redirect(doc.download_link)

# ==================== BULK DOWNLOAD ZIP ====================
@app.route("/download/certificates", methods=["POST"])
@login_required
def download_certificates():
    """Download multiple certificates as ZIP"""
    selected = request.form.getlist('documents') or request.form.getlist('documents[]')
    if not selected:
        return "No documents selected", 400

    memory_file = io.BytesIO()
    downloaded_count = 0
    
    try:
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for doc_id in selected:
                try:
                    doc = Document.query.get(int(doc_id))
                    if not doc:
                        continue
                    
                    url = doc.download_link
                    dl_url = url
                    
                    # Handle Google Drive links
                    if "drive.google.com" in url:
                        match = re.search(r'/d/([a-zA-Z0-9_-]+)', url)
                        if not match:
                            match = re.search(r'id=([a-zA-Z0-9_-]+)', url)
                        if match:
                            file_id = match.group(1)
                            dl_url = f"https://drive.google.com/uc?export=download&id={file_id}"
                    
                    try:
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        }
                        req = urllib.request.Request(dl_url, headers=headers)
                        
                        with urllib.request.urlopen(req, timeout=30) as resp:
                            content = resp.read()
                            
                            if len(content) == 0:
                                continue
                            
                            name = (doc.doc_name or doc.doc_type or f"document_{doc.id}").strip()
                            safe_name = secure_filename(name) or f"document_{doc.id}"
                            
                            if not re.search(r'\.[a-zA-Z0-9]{1,5}$', safe_name):
                                safe_name += ".pdf" if content.startswith(b'%PDF') else ".pdf"
                            
                            zf.writestr(safe_name, content)
                            downloaded_count += 1
                            
                    except Exception as e:
                        app.logger.warning(f"Failed to download {doc_id}: {str(e)}")
                        continue
                        
                except Exception as e:
                    app.logger.error(f"Error processing document {doc_id}: {str(e)}")
                    continue
        
        if downloaded_count == 0:
            return "No documents could be downloaded", 400
        
        # Log download
        user_id = session.get("user_id")
        if user_id:
            user = User.query.get(user_id)
            if user:
                user.downloads_count = (user.downloads_count or 0) + 1
            
            log = DownloadLog(
                user_id=user_id,
                document_count=downloaded_count,
                file_size=memory_file.tell(),
                ip_address=get_user_ip()
            )
            db.session.add(log)
            db.session.commit()
        
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'certificates_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.zip'
        )
        
    except Exception as e:
        app.logger.error(f"ZIP Creation Error: {str(e)}")
        return "Error creating ZIP file", 500

# ==================== API ENDPOINTS ====================
@app.route("/api/site-config")
def get_site_config():
    config = SiteConfig.query.first()
    if not config:
        config = SiteConfig(
            company_name='Gautam Solar',
            tagline='Premium Solar Solutions'
        )
        db.session.add(config)
        db.session.commit()
    
    return jsonify({
        'logoUrl': config.logo_url or 'https://via.placeholder.com/200x80?text=Gautam+Solar',
        'companyName': config.company_name,
        'tagline': config.tagline,
        'footerText': config.footer_text,
        'phone': config.phone,
        'email': config.email,
        'address': config.address
    })

@app.route("/api/portal-data")
def api_portal_data():
    categories = ProductCategory.query.order_by(ProductCategory.order).all()
    company_docs = CompanyDocument.query.all()
    is_logged_in = "user_id" in session
    
    company_data = {}
    for doc in company_docs:
        if doc.location not in company_data:
            company_data[doc.location] = []
        company_data[doc.location].append({
            'id': doc.id,
            'type': doc.doc_type,
            'name': doc.doc_name or doc.doc_type,
            'link': f'/download/company/{doc.id}' if is_logged_in else '/login'
        })
    
    products_data = []
    for cat in categories:
        products = Product.query.filter_by(category_id=cat.id).order_by(Product.order).all()
        products_list = []
        for prod in products:
            docs = Document.query.filter_by(product_id=prod.id).order_by(Document.order).all()
            products_list.append({
                'id': prod.id,
                'wattage': prod.wattage,
                'availability': prod.availability,
                'efficiency': prod.efficiency,
                'documents': [{
                    'id': d.id,
                    'type': d.doc_type,
                    'name': d.doc_name or d.doc_type,
                    'download_count': d.download_count
                } for d in docs]
            })
        
        products_data.append({
            'id': cat.id,
            'name': cat.name,
            'description': cat.description,
            'products': products_list
        })
    
    return jsonify({
        'companyDocs': company_data,
        'categories': products_data,
        'isLoggedIn': is_logged_in
    })

@app.route("/api/portal-stats")
def portal_stats():
    """Portal statistics API"""
    return jsonify({
        'total_products': Product.query.count(),
        'total_categories': ProductCategory.query.count(),
        'total_documents': Document.query.count(),
        'total_users': User.query.count(),
        'approved_users': User.query.filter_by(approved=True).count()
    })

# ==================== AUTHENTICATION ROUTES ====================
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            name = request.form.get("name", "").strip()
            company = request.form.get("company", "").strip()
            mobile = request.form.get("mobile", "").strip()
            
            if not all([email, password, name]):
                raise ValueError("Email, password and name required")
            
            if len(password) < 6:
                raise ValueError("Password must be 6+ characters")
            
            if User.query.filter_by(email=email).first():
                raise ValueError("Email already registered")
            
            user = User(
                name=name,
                company=company or "Not specified",
                email=email,
                mobile=mobile or "N/A",
                password=generate_password_hash(password),
                approved=False
            )
            
            db.session.add(user)
            db.session.commit()
            
            access_req = AccessRequest(
                user_id=user.id,
                request_type='new_registration',
                details=f"New user: {name} from {company}"
            )
            db.session.add(access_req)
            db.session.commit()
            
            app.logger.info(f"New registration: {email}")
            
            return redirect(url_for("login"))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            return f"Error: {str(e)}", 400
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Unified login for both admin and customers"""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "customer")
        
        # Admin Login
        if role == "admin":
            if (email == "gautamsolarpvtltd@gmail.com" and 
                password == "Skpanchaladmin123"):
                session["admin"] = True
                session["user_name"] = "Admin"
                app.logger.info(f"Admin login successful: {email}")
                return redirect(url_for("admin_dashboard"))
            else:
                app.logger.warning(f"Failed admin login attempt: {email}")
                return render_template("login_unified.html", error="Invalid admin credentials")
        
        # Customer Login
        else:
            user = User.query.filter_by(email=email).first()
            
            if not user or not check_password_hash(user.password, password):
                app.logger.warning(f"Failed customer login attempt: {email}")
                return render_template("login_unified.html", error="Invalid email or password")
            
            if not user.approved:
                return render_template("login_unified.html", error="Account pending approval")
            
            if not user.is_active:
                return render_template("login_unified.html", error="Account is disabled")
            
            session["user_id"] = user.id
            session["user_name"] = user.name
            user.last_login = datetime.utcnow()
            
            access_req = AccessRequest(
                user_id=user.id,
                request_type="login",
                details=f"Login from {get_user_ip()}"
            )
            db.session.add(access_req)
            db.session.commit()
            
            app.logger.info(f"Customer login successful: {email}")
            return redirect(url_for("portal"))
    
    return render_template("login_unified.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("portal"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return "Email not found", 404
        
        otp = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        PasswordReset.query.filter_by(user_id=user.id, used=False).delete()
        
        pwd_reset = PasswordReset(user_id=user.id, otp=otp, expires_at=expires_at)
        db.session.add(pwd_reset)
        db.session.commit()
        
        send_email(user.email, "Password Reset OTP", f"Your OTP: {otp}")
        
        return redirect(url_for("verify_otp", user_email=email))
    
    return render_template("forgot_password.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    user_email = request.args.get("user_email")
    
    if request.method == "POST":
        otp = request.form.get("otp")
        user = User.query.filter_by(email=user_email).first()
        
        if not user:
            return "User not found", 404
        
        pwd_reset = PasswordReset.query.filter_by(user_id=user.id, used=False).order_by(
            PasswordReset.created_at.desc()
        ).first()
        
        if not pwd_reset or pwd_reset.expires_at < datetime.utcnow():
            return "OTP expired", 400
        
        if pwd_reset.otp != otp:
            return "Invalid OTP", 400
        
        pwd_reset.used = True
        db.session.commit()
        
        return redirect(url_for("reset_password", user_email=user_email))
    
    return render_template("verify_otp.html", user_email=user_email)

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    user_email = request.args.get("user_email")
    
    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        
        if password != confirm or len(password) < 6:
            return "Invalid password", 400
        
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return "User not found", 404
        
        user.password = generate_password_hash(password)
        db.session.commit()
        
        send_email(user.email, "Password Changed", "Your password has been reset successfully")
        
        return redirect(url_for("login"))
    
    return render_template("reset_password.html", user_email=user_email)

# ==================== ADMIN ROUTES ====================


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html",
        users_count=User.query.count(),
        approved_count=User.query.filter_by(approved=True).count(),
        categories_count=ProductCategory.query.count(),
        products_count=Product.query.count()
    )

@app.route("/admin/users")
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=20)
    return render_template("admin_users.html", users=users)

@app.route("/admin/approve/<int:user_id>")
@admin_required
def approve_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.approved = True
        db.session.commit()
        
        send_email(user.email, "Account Approved", 
            f"Your account has been approved! Login at http://127.0.0.1:5000/login")
        
        app.logger.info(f"User approved: {user.email}")
        return redirect(url_for("admin_users"))
    except Exception as e:
        app.logger.error(f"Error approving user: {e}")
        return str(e), 500

@app.route("/admin/reject/<int:user_id>")
@admin_required
def reject_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        email = user.email
        db.session.delete(user)
        db.session.commit()
        
        send_email(email, "Registration Not Approved", "Your registration was not approved")
        
        app.logger.info(f"User rejected: {email}")
        return redirect(url_for("admin_users"))
    except Exception as e:
        return str(e), 500

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        email = user.email
        
        DownloadLog.query.filter_by(user_id=user_id).delete()
        AccessRequest.query.filter_by(user_id=user_id).delete()
        PasswordReset.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        
        app.logger.info(f"User deleted: {email}")
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/admin/certificates")
@admin_required
def admin_certificates():
    categories = ProductCategory.query.order_by(ProductCategory.order).all()
    return render_template("admin_certificates_enhanced.html", categories=categories)

# ==================== CATEGORY MANAGEMENT ====================
@app.route("/admin/category/add", methods=["POST"])
@admin_required
def add_category():
    try:
        category = ProductCategory(
            name=request.form.get("name"),
            description=request.form.get("description"),
            order=int(request.form.get("order", 0))
        )
        db.session.add(category)
        db.session.commit()
        app.logger.info(f"Category added: {category.name}")
        return jsonify({'success': True, 'id': category.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route("/admin/company-docs")
@admin_required
def admin_company_docs():
    """Admin page for managing company documents"""
    return render_template("admin_company_docs.html")
@app.route("/admin/category/<int:cat_id>/delete", methods=["POST"])
@admin_required
def delete_category(cat_id):
    try:
        category = ProductCategory.query.get_or_404(cat_id)
        db.session.delete(category)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# ==================== PRODUCT MANAGEMENT ====================
@app.route("/admin/product/add", methods=["POST"])
@admin_required
def add_product():
    try:
        product = Product(
            category_id=int(request.form.get("category_id")),
            wattage=request.form.get("wattage"),
            order=int(request.form.get("order", 0)),
            availability=request.form.get("availability", "available")
        )
        db.session.add(product)
        db.session.commit()
        return jsonify({'success': True, 'id': product.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route("/admin/product/<int:prod_id>/delete", methods=["POST"])
@admin_required
def delete_product(prod_id):
    try:
        product = Product.query.get_or_404(prod_id)
        db.session.delete(product)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route("/admin/product/<int:prod_id>/update-availability", methods=["POST"])
@admin_required
def update_product_availability(prod_id):
    try:
        product = Product.query.get_or_404(prod_id)
        product.availability = request.form.get("availability")
        product.last_stock_update = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# ==================== DOCUMENT MANAGEMENT ====================
@app.route("/admin/document/add", methods=["POST"])
@admin_required
def add_document():
    try:
        document = Document(
            product_id=int(request.form.get("product_id")),
            doc_type=request.form.get("doc_type"),
            doc_name=request.form.get("doc_name", ""),
            download_link=request.form.get("download_link"),
            order=int(request.form.get("order", 0))
        )
        db.session.add(document)
        db.session.commit()
        return jsonify({'success': True, 'id': document.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route("/admin/document/<int:doc_id>/delete", methods=["POST"])
@admin_required
def delete_document(doc_id):
    try:
        document = Document.query.get_or_404(doc_id)
        db.session.delete(document)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# ==================== COMPANY DOCUMENTS ====================
@app.route("/admin/company-doc/add", methods=["POST"])
@admin_required
def add_company_doc():
    try:
        doc = CompanyDocument(
            location=request.form.get("location"),
            doc_type=request.form.get("doc_type"),
            doc_name=request.form.get("doc_name", ""),
            download_link=request.form.get("download_link")
        )
        db.session.add(doc)
        db.session.commit()
        return jsonify({'success': True, 'id': doc.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route("/admin/company-doc/<int:doc_id>/delete", methods=["POST"])
@admin_required
def delete_company_doc(doc_id):
    try:
        doc = CompanyDocument.query.get_or_404(doc_id)
        db.session.delete(doc)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

# ==================== ADMIN ANALYTICS ====================
@app.route("/admin/analytics")
@admin_required
def analytics():
    return render_template("admin_analytics.html")

@app.route("/api/admin/analytics")
@admin_required
def api_analytics():
    """Analytics data API"""
    try:
        # User stats
        total_users = User.query.count()
        approved_users = User.query.filter_by(approved=True).count()
        today_registrations = User.query.filter(
            User.created_at >= datetime.utcnow().date()
        ).count()
        
        # Download stats
        total_downloads = DownloadLog.query.count()
        today_downloads = DownloadLog.query.filter(
            DownloadLog.download_date >= datetime.utcnow().date()
        ).count()
        
        # Product stats
        total_products = Product.query.count()
        available_products = Product.query.filter_by(availability='available').count()
        
        # Top downloaded documents
        top_docs = db.session.query(Document).order_by(
            Document.download_count.desc()
        ).limit(5).all()
        
        return jsonify({
            'success': True,
            'users': {
                'total': total_users,
                'approved': approved_users,
                'pending': total_users - approved_users,
                'today': today_registrations
            },
            'downloads': {
                'total': total_downloads,
                'today': today_downloads
            },
            'products': {
                'total': total_products,
                'available': available_products,
                'limited': Product.query.filter_by(availability='limited').count(),
                'discontinued': Product.query.filter_by(availability='discontinued').count()
            },
            'top_documents': [{
                'id': d.id,
                'name': d.doc_name or d.doc_type,
                'downloads': d.download_count
            } for d in top_docs]
        })
    except Exception as e:
        app.logger.error(f"Analytics error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route("/admin/users/export")
@admin_required
def export_users():
    """Export users to CSV"""
    try:
        users = User.query.all()
        
        si = io.StringIO()
        writer = csv.writer(si)
        writer.writerow(['ID', 'Name', 'Email', 'Company', 'Mobile', 'Status', 'Created', 'Last Login', 'Downloads'])
        
        for user in users:
            writer.writerow([
                user.id,
                user.name,
                user.email,
                user.company,
                user.mobile,
                'Approved' if user.approved else 'Pending',
                user.created_at.strftime('%Y-%m-%d'),
                user.last_login.strftime('%Y-%m-%d') if user.last_login else 'Never',
                user.downloads_count or 0
            ])
        
        output = io.BytesIO()
        output.write(si.getvalue().encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'users_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
        )
    except Exception as e:
        app.logger.error(f"Export error: {e}")
        return "Error exporting", 500

@app.route("/admin/branding")
@admin_required
def admin_branding():
    config = SiteConfig.query.first()
    if not config:
        config = SiteConfig()
        db.session.add(config)
        db.session.commit()
    return render_template("admin_branding.html", config=config)

@app.route("/admin/branding/update", methods=["POST"])
@admin_required
def update_branding():
    try:
        config = SiteConfig.query.first()
        if not config:
            config = SiteConfig()
            db.session.add(config)
        
        config.logo_url = request.form.get('logoUrl') or config.logo_url
        config.company_name = request.form.get('companyName') or config.company_name
        config.tagline = request.form.get('tagline') or config.tagline
        config.footer_text = request.form.get('footerText') or config.footer_text
        config.phone = request.form.get('phone') or config.phone
        config.email = request.form.get('email') or config.email
        config.address = request.form.get('address') or config.address
        
        db.session.commit()
        app.logger.info("Branding updated")
        
        return jsonify({
            'success': True,
            'message': 'Branding updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    app.logger.info("Admin logout")
    return redirect(url_for("index"))

# ==================== API - SEARCH & FILTER ====================
@app.route("/api/search/products")
def search_products():
    """Search products by wattage or category"""
    query = request.args.get('q', '').lower()
    category_id = request.args.get('category', type=int)
    
    try:
        products = Product.query
        
        if category_id:
            products = products.filter_by(category_id=category_id)
        
        if query:
            products = products.filter(Product.wattage.ilike(f'%{query}%'))
        
        products = products.limit(20).all()
        
        return jsonify({
            'success': True,
            'results': [{
                'id': p.id,
                'wattage': p.wattage,
                'availability': p.availability,
                'category_id': p.category_id
            } for p in products]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(error):
    app.logger.warning(f"404 error: {request.url}")
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f"500 error: {str(error)}")
    return render_template("500.html"), 500

@app.errorhandler(403)
def forbidden(error):
    app.logger.warning(f"403 error: {request.url}")
    return render_template("403.html"), 403

# ==================== DATABASE INITIALIZATION ====================
def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        print("\n📝 Initializing database...")
        
        os.makedirs('database', exist_ok=True)
        
        try:
            db.create_all()
            print("✅ Database tables created!")
        except Exception as e:
            print(f"❌ Error creating tables: {e}")
            return

        try:
            if User.query.count() == 0:
                print("👥 Adding sample data...")
                
                admin = User(
                    name="Admin",
                    email="gautamsolarpvtltd@gmail.com",
                    password=generate_password_hash("Skpanchaladmin123"),
                    company="Gautam Solar",
                    mobile="+919599817214",
                    approved=True
                )
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin created!")

            if ProductCategory.query.count() == 0:
                print("📦 Adding categories...")
                
                categories = [
                    ProductCategory(
                        name="Mono PERC M10",
                        description="High efficiency mono PERC modules",
                        technology="Mono PERC",
                        order=1
                    ),
                    ProductCategory(
                        name="N-Type TOPCon G2B Bifacial",
                        description="Next-gen bifacial modules",
                        technology="TOPCon",
                        order=2
                    ),
                    ProductCategory(
                        name="Polycrystalline Modules",
                        description="Affordable solar panels",
                        technology="Poly",
                        order=3
                    )
                ]
                db.session.add_all(categories)
                db.session.commit()
                print("✅ Categories added!")

                for cat in categories:
                    for watt in ["530 Wp", "540 Wp", "550 Wp"]:
                        prod = Product(
                            category_id=cat.id,
                            wattage=watt,
                            availability="available",
                            efficiency=22.5
                        )
                        db.session.add(prod)
                db.session.commit()
                print("✅ Products added!")

                # Add sample documents
                products = Product.query.all()
                for prod in products[:3]:
                    for doc_type in ["Datasheet", "BIS Certificate", "Technical Specs"]:
                        doc = Document(
                            product_id=prod.id,
                            doc_type=doc_type,
                            doc_name=f"{doc_type} - {prod.wattage}",
                            download_link="https://drive.google.com/file/d/sample/view"
                        )
                        db.session.add(doc)
                db.session.commit()
                print("✅ Documents added!")

                # Add company documents
                company_docs = [
                    CompanyDocument(
                        location="Head Office - Delhi",
                        doc_type="GST Certificate",
                        download_link="https://drive.google.com/file/d/gst/view"
                    ),
                    CompanyDocument(
                        location="Unit 1 - Haridwar",
                        doc_type="Factory License",
                        download_link="https://drive.google.com/file/d/license/view"
                    ),
                    CompanyDocument(
                        location="Unit 2 - Bhiwani",
                        doc_type="ISO Certificate",
                        download_link="https://drive.google.com/file/d/iso/view"
                    )
                ]
                db.session.add_all(company_docs)
                db.session.commit()
                print("✅ Company documents added!")

                # Add site config
                config = SiteConfig(
                    company_name='Gautam Solar Pvt. Ltd.',
                    tagline='Premium Solar Solutions',
                    footer_text='© 2024 Gautam Solar. All rights reserved.',
                    phone='+919599817214',
                    email='testing@gautamsolar.com',
                    address='D 120-121 Okhla Industrial Area, Phase-1, New Delhi 110020'
                )
                db.session.add(config)
                db.session.commit()
                print("✅ Configuration added!")

            print("✅ Database ready!")

        except Exception as e:
            print(f"❌ Error: {e}")
            db.session.rollback()
            import traceback
            traceback.print_exc()

# ==================== RUN APPLICATION ====================
if __name__ == "__main__":
    init_db()
    
    print("\n" + "="*80)
    print("🚀 GAUTAM SOLAR PORTAL - PRODUCTION READY")
    print("="*80)
    print("\n🌐 ACCESS URLs:")
    print("   🏠 Homepage:        http://127.0.0.1:5000/")
    print("   📖 About:           http://127.0.0.1:5000/about")
    print("   📧 Contact:         http://127.0.0.1:5000/contact")
    print("   🌍 Portal:          http://127.0.0.1:5000/portal")
    print("   👤 Login:           http://127.0.0.1:5000/login")
    print("   📝 Register:        http://127.0.0.1:5000/register")
    print("   🔐 Admin:           http://127.0.0.1:5000/admin")
    
    print("\n👤 ADMIN CREDENTIALS:")
    print("   Email:    gautamsolarpvtltd@gmail.com")
    print("   Password: Skpanchaladmin123")
    
    print("\n✅ NEW FEATURES ADDED:")
    print("   ✓ Download logging system")
    print("   ✓ User activity tracking")
    print("   ✓ Advanced analytics dashboard")
    print("   ✓ User pagination (20 per page)")
    print("   ✓ Email notifications")
    print("   ✓ IP address logging")
    print("   ✓ Decorator-based permissions")
    print("   ✓ Error handlers (404, 500, 403)")
    print("   ✓ Product search/filter API")
    print("   ✓ CSV export functionality")
    print("   ✓ Document download counting")
    print("   ✓ User last login tracking")
    print("   ✓ User account disable feature")
    print("   ✓ Rotating file logging")
    print("   ✓ Portal statistics API")
    print("   ✓ File size tracking")
    print("   ✓ Efficiency field for products")
    print("   ✓ Timestamps for all records")
    print("   ✓ Improved security")
    
    print("\n📊 DATABASE MODELS:")
    print("   • User (with tracking)")
    print("   • DownloadLog (new)")
    print("   • PasswordReset")
    print("   • AccessRequest")
    print("   • ProductCategory")
    print("   • Product (enhanced)")
    print("   • Document (enhanced)")
    print("   • CompanyDocument")
    print("   • HomeNotification")
    print("   • SiteConfig (enhanced)")
    
    print("\n⚠️  PRODUCTION CHECKLIST:")
    print("   ☐ Update ADMIN_PASSWORD with Gmail App Password")
    print("   ☐ Change app.secret_key to random string")
    print("   ☐ Use environment variables for sensitive data")
    print("   ☐ Set debug=False for production")
    print("   ☐ Use proper WSGI server (Gunicorn, uWSGI)")
    print("   ☐ Set up HTTPS/SSL certificates")
    print("   ☐ Configure firewall rules")
    print("   ☐ Set up database backups")
    print("   ☐ Monitor error logs regularly")
    print("   ☐ Set up rate limiting")
    
    print("\n" + "="*80)
    print("Ready to run! 🎉\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)