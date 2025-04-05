from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
import shutil
import click
from werkzeug.utils import secure_filename
import uuid
from flask_login import UserMixin
from functools import wraps

# 创建 Flask 应用实例
app = Flask(__name__)

# 从配置文件加载配置
app.config.from_object('config')

# 确保从配置文件加载了管理员用户
from config import ADMIN_USERS
app.config['ADMIN_USERS'] = ADMIN_USERS

# 设置默认管理员用户名
ADMIN_USERNAME = 'test'  # 默认管理员用户名

# 其他配置
app.config['SECRET_KEY'] = 'your-secret-key'  # 建议使用更强的密钥
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/items.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # session过期时间为7天
app.config['SESSION_TYPE'] = 'filesystem'  # 使用文件系统存储session
app.config['SESSION_PERMANENT'] = True  # 默认使用永久session

# 确保上传文件夹存在
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# 确保instance文件夹存在
if not os.path.exists('instance'):
    os.makedirs('instance')

# 初始化数据库
db = SQLAlchemy()
db.init_app(app)
migrate = Migrate(app, db)

# 登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': '请先登录'}), 401
            flash('请先登录')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# 定义数据库模型
class User(db.Model):
    __tablename__ = 'user'  # 明确指定表名为小写
    id = db.Column(db.String(80), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    is_authorized = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    show_sold_items = db.Column(db.Boolean, default=True)
    ever_authorized = db.Column(db.Boolean, default=False)
    items = db.relationship('Item', backref='owner', lazy=True, 
                          foreign_keys='Item.user_id',
                          cascade='all, delete-orphan')
    reserved_items = db.relationship('Item', backref='reserver', lazy=True,
                                   foreign_keys='Item.reserved_by',
                                   cascade='all, delete-orphan')
    reservations = db.relationship('Reservation', backref='user', lazy=True,
                                 cascade='all, delete-orphan')

    def __init__(self, id, username):
        self.id = id
        self.username = username
        self.is_admin = False  # 默认非管理员
        self.is_authorized = False  # 默认未授权
        self.show_sold_items = True
        self.created_at = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.login_count = 0
        self.ever_authorized = False

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_online(self):
        return (datetime.utcnow() - self.last_seen) <= timedelta(minutes=5)

    def get_reserved_items(self):
        active_reservations = Reservation.query.filter_by(
            user_id=self.id,
            is_active=True
        ).order_by(Reservation.expires_at.asc()).all()
        return active_reservations

    def get_total_reserved_price(self):
        active_reservations = self.get_reserved_items()
        return sum(r.item.price for r in active_reservations if r.item)

    def get_active_items_count(self):
        """获取用户当前在售物品数量"""
        return Item.query.filter_by(user_id=self.id, is_sold=False).count()

    def get_sold_items_count(self):
        """获取用户已售出物品数量"""
        return Item.query.filter_by(user_id=self.id, is_sold=True).count()

    def get_active_reservations_count(self):
        """获取用户当前有效预定数量"""
        return Reservation.query.filter_by(user_id=self.id, is_active=True).count()

    def get_pending_auth_requests(self):
        """获取管理员收到的待处理授权申请"""
        return AuthRequest.query.filter_by(
            admin_id=self.id,
            status='pending'
        ).order_by(AuthRequest.created_at.desc()).all()

    def has_pending_request(self, admin_id):
        """检查用户是否有待处理的授权申请"""
        return AuthRequest.query.filter_by(
            user_id=self.id,
            admin_id=admin_id,
            status='pending'
        ).first() is not None

    def __repr__(self):
        """用于在数据库中直观显示用户信息"""
        status = "在线" if self.is_online() else "离线"
        auth_status = "已授权" if self.is_authorized else "未授权"
        return f"用户[{self.username}] - {status}/{auth_status} - 登录{self.login_count}次 - 注册于{self.created_at.strftime('%Y-%m-%d')}"

class Item(db.Model):
    __tablename__ = 'item'  # 明确指定表名为小写
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(20), nullable=False)
    image_path = db.Column(db.String(200), nullable=False)
    is_reserved = db.Column(db.Boolean, default=False)
    is_sold = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=False)
    reserved_by = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=True)
    reservations = db.relationship('Reservation', backref='item', lazy=True,
                                 cascade='all, delete-orphan')

class Reservation(db.Model):
    __tablename__ = 'reservation'  # 明确指定表名为小写
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def __init__(self, user_id, item_id):
        self.user_id = user_id
        self.item_id = item_id
        self.created_at = datetime.utcnow()
        self.expires_at = self.created_at + timedelta(hours=72)

    def get_remaining_time(self):
        now = datetime.utcnow()
        if now > self.expires_at:
            return timedelta()
        return self.expires_at - now

# 设置关系
User.items = db.relationship('Item', backref='owner', lazy=True,
                           foreign_keys='Item.user_id',
                           cascade='all, delete-orphan')
User.reserved_items = db.relationship('Item', backref='reserver', lazy=True,
                                    foreign_keys='Item.reserved_by',
                                    cascade='all, delete-orphan')
User.reservations = db.relationship('Reservation', backref='user', lazy=True,
                                  cascade='all, delete-orphan')
Item.reservations = db.relationship('Reservation', backref='item', lazy=True,
                                  cascade='all, delete-orphan')

class AuthRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=False)
    admin_id = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='sent_requests')
    admin = db.relationship('User', foreign_keys=[admin_id], backref='received_requests')

# 在应用上下文中创建所有数据库表
with app.app_context():
    db.create_all()
    print("数据库表已创建")

@app.before_request
def check_user_status():
    # 不需要登录就能访问的路由
    public_routes = ['index', 'login', 'register', 'static', 'admin_login']
    
    # 设置全局用户对象
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()
            g.user = user  # 将用户对象存储在 g 对象中
        else:
            session.clear()
            g.user = None
    else:
        g.user = None
    
    # 如果是公开路由，不需要检查登录状态
    if request.endpoint in public_routes:
        return
    
    # 检查用户是否登录
    if not g.user:
        flash('请先登录')
        return redirect(url_for('login', next=request.url))

@app.context_processor
def inject_user():
    # 获取管理员用户
    admin_user = User.query.filter_by(is_admin=True).first()
    return dict(current_user=g.user, admin_user=admin_user)

@app.route('/')
def index():
    # 获取搜索参数
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    sort = request.args.get('sort', 'newest')
    reserved = request.args.get('reserved', 'false') == 'true'
    
    # 构建查询
    query = Item.query.filter_by(is_sold=False)
    
    # 根据预定状态过滤
    if reserved:
        # 在已预定标签中，只显示被授权用户预定的物品
        query = query.join(User, User.id == Item.reserved_by).filter(
            Item.is_reserved == True,
            User.is_authorized == True
        )
    else:
        # 在可预定标签中，显示未被预定的物品，以及被未授权用户预定的物品
        query = query.outerjoin(User, User.id == Item.reserved_by).filter(
            db.or_(
                Item.is_reserved == False,
                User.is_authorized == False
            )
        )
    
    if search:
        query = query.filter(Item.title.ilike(f'%{search}%'))
    if category:
        query = query.filter(Item.category == category)
        
    # 排序
    if sort == 'price_low':
        query = query.order_by(Item.price.asc())
    elif sort == 'price_high':
        query = query.order_by(Item.price.desc())
    else:  # newest
        query = query.order_by(Item.created_at.desc())
    
    items = query.all()
    
    # 获取在线和离线用户列表
    all_users = User.query.all()
    online_users = [user for user in all_users if user.is_online()]
    offline_users = [user for user in all_users if not user.is_online()]
    
    return render_template('index.html', 
                         items=items, 
                         current_category=category,
                         current_sort=sort,
                         search=search,
                         online_users=online_users,
                         offline_users=offline_users)

@app.route('/my_reservations')
def my_reservations():
    reservations = g.user.get_reserved_items()
    total_price = g.user.get_total_reserved_price()
    return render_template('my_reservations.html', 
                         reservations=reservations, 
                         total_price=total_price)

@app.route('/check_session')
def check_session():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'logged_in': 'user_id' in session})
    return redirect(url_for('index'))

@app.route('/get_users')
def get_users():
    """AJAX请求获取用户列表"""
    users = User.query.all()
    online_users = [user for user in users if user.is_online()]
    offline_users = [user for user in users if not user.is_online()]
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'online_users': [{'id': user.id, 'username': user.username} for user in online_users],
            'offline_users': [{'id': user.id, 'username': user.username} for user in offline_users]
        })
    
    return render_template('users.html', online_users=online_users, offline_users=offline_users)

@app.route('/users')
def users():
    """显示用户列表页面"""
    users = User.query.all()
    online_users = [user for user in users if user.is_online()]
    offline_users = [user for user in users if not user.is_online()]
    return render_template('users.html', online_users=online_users, offline_users=offline_users)

@app.route('/user/<string:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    admin_user = User.query.filter_by(username='test').first()
    
    # 获取用户的物品
    active_items = [item for item in user.items if not item.is_sold]
    sold_items = [item for item in user.items if item.is_sold]
    
    return render_template('user_profile.html', 
                         user=user, 
                         admin_user=admin_user,
                         active_items=active_items, 
                         sold_items=sold_items)

@app.route('/toggle_show_sold')
def toggle_show_sold():
    if 'user_id' not in session:
        flash('请先登录')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user:
        user.show_sold_items = not user.show_sold_items
        db.session.commit()
        flash('设置已更新')
    return redirect(url_for('user_profile', user_id=user.id))

@app.route('/mark_as_sold/<int:item_id>')
def mark_as_sold(item_id):
    if 'user_id' not in session:
        flash('请先登录')
        return redirect(url_for('login'))
        
    item = Item.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash('您没有权限修改该物品')
        return redirect(url_for('index'))
        
    item.is_sold = True
    item.is_reserved = False
    db.session.commit()
    flash('物品已标记为已售出')
    return redirect(url_for('user_profile', user_id=item.user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 检查是否是管理员用户名
        if username in app.config['ADMIN_USERS']:
            flash('请使用管理员登录入口')
            return redirect(url_for('admin_login'))
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            user.login_count += 1
            user.last_login_at = datetime.utcnow()
            user.last_seen = datetime.utcnow()
            
            # 检查用户授权状态
            if not user.is_authorized:
                if user.ever_authorized:
                    # 曾经被授权过，但现在被取消授权
                    session['deauthorized'] = True
                    flash('您的授权已被取消，无法发布和预定物品。')
                else:
                    # 从未被授权过的用户
                    session['new_user'] = True
            
            db.session.commit()
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            # 设置最后在线时间为很久以前，确保显示为离线
            user.last_seen = datetime.utcnow() - timedelta(minutes=10)
            db.session.commit()
    
    # 完全清除会话
    session.clear()
    
    # 如果是 AJAX 请求，返回 JSON 响应
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return {'status': 'success', 'message': '已退出登录'}
    
    flash('已退出登录')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if not g.user.is_authorized:
        # 获取 admin 用户
        admin = User.query.filter_by(username='admin').first()
        if admin:
            flash(f'您还没有获得发布权限，请联系管理员申请授权：<a href="{url_for("user_profile", user_id=admin.id)}">联系管理员</a>')
        else:
            flash('您还没有获得发布权限。目前系统中还没有管理员账号，请等待管理员账号创建后再申请授权。')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        category = request.form.get('category')
        image = request.files.get('image')
        
        if not all([title, description, price, category, image]):
            flash('请填写所有必填字段')
            return redirect(url_for('upload'))
        
        try:
            price = float(price)
        except ValueError:
            flash('价格必须是数字')
            return redirect(url_for('upload'))
        
        if image:
            # 确保文件名安全
            filename = secure_filename(image.filename)
            # 生成唯一的文件名
            unique_filename = f"{uuid.uuid4()}_{filename}"
            # 保存图片
            image_path = os.path.join('static/uploads', unique_filename)
            os.makedirs(os.path.dirname(image_path), exist_ok=True)
            image.save(image_path)
            
            # 创建新物品
            new_item = Item(
                title=title,
                description=description,
                price=price,
                category=category,
                image_path=f"uploads/{unique_filename}",
                user_id=g.user.id
            )
            db.session.add(new_item)
            db.session.commit()
            
            flash('物品发布成功！')
            return redirect(url_for('index'))
        
    return render_template('upload.html')

@app.route('/reserve/<int:item_id>', methods=['POST'])
def reserve(item_id):
    if not g.user:
        if request.is_json:
            return jsonify({'success': False, 'message': '请先登录'}), 401
        return redirect(url_for('login'))
    
    # 检查用户是否已授权
    if not g.user.is_authorized:
        if request.is_json:
            return jsonify({'success': False, 'message': '您还没有获得预定权限，请联系管理员申请授权'}), 403
        flash('您还没有获得预定权限，请联系管理员申请授权')
        return redirect(url_for('index'))
    
    item = Item.query.get_or_404(item_id)
    
    if item.user_id == g.user.id:
        if request.is_json:
            return jsonify({'success': False, 'message': '不能预定自己的物品'}), 400
        flash('不能预定自己的物品')
        return redirect(url_for('index'))
    
    if item.is_reserved:
        if request.is_json:
            return jsonify({'success': False, 'message': '该物品已被预定'}), 400
        flash('该物品已被预定')
        return redirect(url_for('index'))
    
    item.is_reserved = True
    item.reserved_by = g.user.id
    db.session.commit()
    
    if request.is_json:
        return jsonify({'success': True, 'message': '预定成功'})
    
    flash('预定成功！')
    return redirect(url_for('index'))

@app.route('/cancel/<int:item_id>')
def cancel(item_id):
    if 'user_id' not in session:
        flash('请先登录')
        return redirect(url_for('login'))
        
    item = Item.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash('您没有权限取消预定')
        return redirect(url_for('index'))
        
    if item.is_reserved:
        item.is_reserved = False
        # 取消相关的预定记录
        reservations = Reservation.query.filter_by(item_id=item.id, is_active=True).all()
        for reservation in reservations:
            reservation.is_active = False
        db.session.commit()
        flash('预定已取消')
    return redirect(url_for('index'))

@app.route('/delete/<int:item_id>')
def delete(item_id):
    if 'user_id' not in session:
        flash('请先登录')
        return redirect(url_for('login'))
        
    item = Item.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash('您没有权限删除该物品')
        return redirect(url_for('index'))
        
    # 删除图片文件
    try:
        os.remove(os.path.join('static', item.image_path))
    except:
        pass
    db.session.delete(item)
    db.session.commit()
    flash('物品已删除')
    return redirect(url_for('index'))

@app.route('/delete_account')
def delete_account():
    if 'user_id' not in session:
        flash('请先登录')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(session['user_id'])
    
    # 删除用户上传的所有图片
    for item in user.items:
        if item.image_path:
            try:
                os.remove(os.path.join('static', item.image_path))
            except:
                pass
    
    # 删除用户数据
    db.session.delete(user)
    db.session.commit()
    
    # 清除会话
    session.clear()
    flash('账户已成功删除')
    return redirect(url_for('index'))

@app.route('/authorize_user/<string:user_id>', methods=['POST'])
def authorize_user(user_id):
    if not g.user or not g.user.is_admin:
        flash('您没有权限执行此操作')
        return redirect(url_for('users'))
    
    user = User.query.get_or_404(user_id)
    user.is_authorized = True
    user.ever_authorized = True  # 标记为曾经被授权过
    db.session.commit()
    flash(f'已授权用户 {user.username}')
    return redirect(url_for('users'))

@app.route('/deauthorize_user/<string:user_id>', methods=['POST'])
def deauthorize_user(user_id):
    if not g.user or not g.user.is_admin:
        flash('您没有权限执行此操作')
        return redirect(url_for('users'))
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('不能取消管理员的授权')
        return redirect(url_for('users'))
    
    user.is_authorized = False
    # 注意：不修改ever_authorized字段，保持为True
    
    # 取消该用户的所有预定
    reserved_items = Item.query.filter_by(reserved_by=user.id, is_reserved=True).all()
    for item in reserved_items:
        item.is_reserved = False
        item.reserved_by = None
    
    db.session.commit()
    flash(f'已取消用户 {user.username} 的授权')
    return redirect(url_for('users'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 检查用户名是否为空
        if not username:
            flash('用户名不能为空')
            return redirect(url_for('register'))
            
        # 检查用户名长度
        if len(username) > 80:
            flash('用户名长度不能超过80个字符')
            return redirect(url_for('register'))
            
        # 检查密码是否为空
        if not password:
            flash('密码不能为空')
            return redirect(url_for('register'))
        
        # 检查是否是管理员用户名
        if username in app.config['ADMIN_USERS']:
            flash('该用户名已被系统保留，请使用其他用户名')
            return redirect(url_for('register'))
        
        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已被注册，请使用其他用户名')
            return redirect(url_for('register'))
            
        # 创建新用户
        user = User(id=str(uuid.uuid4()), username=username)
        user.set_password(password)
        user.is_authorized = False
        user.ever_authorized = False  # 明确设置为从未被授权
        db.session.add(user)
        db.session.commit()
        
        # 直接登录用户
        session['user_id'] = user.id
        
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/toggle_sidebar', methods=['POST'])
def toggle_sidebar():
    data = request.get_json()
    if data and 'hidden' in data:
        session['sidebar_hidden'] = data['hidden']
    return jsonify({'status': 'success'})

@app.route('/toggle_tools', methods=['POST'])
def toggle_tools():
    data = request.get_json()
    if data and 'expanded' in data:
        session['tools_expanded'] = data['expanded']
    return jsonify({'status': 'success'})

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """管理员登录"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 检查是否是配置文件中的管理员
        if username in app.config['ADMIN_USERS']:
            admin_info = app.config['ADMIN_USERS'][username]
            if password == admin_info['password']:
                # 检查用户是否存在
                user = User.query.filter_by(username=username).first()
                if not user:
                    # 如果管理员用户不存在，创建一个新的管理员用户
                    user = User(id=str(uuid.uuid4()), username=username)
                    user.set_password(admin_info['password'])  # 使用配置文件中的密码
                    user.is_admin = True
                    user.is_authorized = True
                    db.session.add(user)
                    db.session.commit()
                elif not user.is_admin:
                    # 如果用户存在但不是管理员，更新为管理员
                    user.is_admin = True
                    user.is_authorized = True
                    user.set_password(admin_info['password'])  # 更新密码
                    db.session.commit()
                
                # 更新登录信息
                user.login_count += 1
                user.last_login_at = datetime.utcnow()
                user.last_seen = datetime.utcnow()
                db.session.commit()
                
                session['user_id'] = user.id
                flash('管理员登录成功')
                return redirect(url_for('index'))
            else:
                flash('管理员密码错误')
        else:
            flash('该用户不是管理员')
        
    return render_template('admin_login.html')

@app.route('/request-auth/<string:admin_id>', methods=['POST'])
@login_required
def request_auth(admin_id):
    if g.user.is_admin or g.user.is_authorized:
        return jsonify({
            'success': False,
            'message': '您已经是管理员或已获得授权，无需申请'
        })

    admin = User.query.get_or_404(admin_id)
    if not admin.is_admin:
        return jsonify({
            'success': False,
            'message': '指定用户不是管理员'
        })

    if g.user.has_pending_request(admin_id):
        return jsonify({
            'success': False,
            'message': '您已经向该管理员提交了申请，请耐心等待'
        })

    message = request.form.get('message', '')
    auth_request = AuthRequest(
        user_id=g.user.id,
        admin_id=admin_id,
        message=message,
        status='pending'
    )
    db.session.add(auth_request)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': '授权申请已提交，请等待管理员审核'
    })

@app.route('/auth-requests')
@login_required
def auth_requests():
    if not g.user.is_admin:
        flash('只有管理员可以查看授权申请列表', 'error')
        return redirect(url_for('index'))
    
    pending_requests = AuthRequest.query.filter_by(
        admin_id=g.user.id,
        status='pending'
    ).order_by(AuthRequest.created_at.desc()).all()
    
    return render_template('auth_requests.html', requests=pending_requests)

@app.route('/process-auth-request/<int:request_id>/<action>')
@login_required
def process_auth_request(request_id, action):
    if not g.user.is_admin:
        flash('只有管理员可以处理授权申请', 'error')
        return redirect(url_for('index'))
    
    auth_request = AuthRequest.query.get_or_404(request_id)
    if auth_request.admin_id != g.user.id:
        flash('您无权处理该授权申请', 'error')
        return redirect(url_for('auth_requests'))
    
    user = User.query.get(auth_request.user_id)
    if not user:
        flash('申请用户不存在', 'error')
        return redirect(url_for('auth_requests'))

    if action == 'approve':
        user.is_authorized = True
        user.ever_authorized = True
        auth_request.status = 'approved'
        auth_request.processed_at = datetime.utcnow()
        flash(f'已批准 {user.username} 的授权申请', 'success')
    elif action == 'reject':
        auth_request.status = 'rejected'
        auth_request.processed_at = datetime.utcnow()
        flash(f'已拒绝 {user.username} 的授权申请', 'info')
    else:
        flash('无效的操作', 'error')
        return redirect(url_for('auth_requests'))

    db.session.commit()
    return redirect(url_for('auth_requests'))

@app.route('/user-list')
@login_required
def user_list():
    """显示用户列表页面"""
    users = User.query.all()
    return render_template('user_list.html', users=users)

@app.cli.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    db.drop_all()
    db.create_all()
    click.echo('Initialized the database.')

@app.before_first_request
def init_admin():
    """确保管理员用户存在"""
    with app.app_context():
        admin = User.query.filter_by(username=ADMIN_USERNAME).first()
        if admin:
            admin.is_admin = True
            admin.is_authorized = True  # 确保管理员也被授权
            db.session.commit()
        
@app.route('/notify_admin/<int:admin_id>', methods=['POST'])
def notify_admin(admin_id):
    if not g.user:
        return jsonify({'status': 'error', 'message': '请先登录'}), 401
        
    admin = User.query.get_or_404(admin_id)
    if not admin.is_admin:
        return jsonify({'status': 'error', 'message': '指定用户不是管理员'}), 400
        
    # 检查是否已经有待处理的请求
    existing_request = AuthRequest.query.filter_by(
        user_id=g.user.id,
        admin_id=admin_id,
        status='pending'
    ).first()
    
    if existing_request:
        return jsonify({'status': 'info', 'message': '已经发送过申请，请等待管理员处理'}), 200
        
    # 创建新的授权请求
    auth_request = AuthRequest(
        user_id=g.user.id,
        admin_id=admin_id,
        status='pending'
    )
    
    try:
        db.session.add(auth_request)
        db.session.commit()
        return jsonify({'status': 'success', 'message': '已通知管理员'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': '发送申请失败，请稍后重试'}), 500

if __name__ == '__main__':
    with app.app_context():
        # 只在数据库不存在时创建
        if not os.path.exists('instance/items.db'):
            db.create_all()
            print("数据库已创建")
    app.run(debug=True) 