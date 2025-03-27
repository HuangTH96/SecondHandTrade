from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 设置session过期时间为7天
db = SQLAlchemy(app)

# 确保上传文件夹存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    show_sold_items = db.Column(db.Boolean, default=True)  # 是否显示已售物品
    items = db.relationship('Item', backref='owner', lazy=True)

    def is_online(self):
        return (datetime.utcnow() - self.last_seen) < timedelta(minutes=5)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(20), nullable=False)
    image_path = db.Column(db.String(200), nullable=False)
    is_reserved = db.Column(db.Boolean, default=False)
    is_sold = db.Column(db.Boolean, default=False)  # 新增：是否已售
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

@app.before_request
def before_request():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.last_seen = datetime.utcnow()
            db.session.commit()

@app.route('/')
def index():
    search_query = request.args.get('search', '')
    if search_query:
        items = Item.query.filter(Item.title.ilike(f'%{search_query}%')).filter_by(is_sold=False).order_by(Item.created_at.desc()).all()
    else:
        items = Item.query.filter_by(is_sold=False).order_by(Item.created_at.desc()).all()
    return render_template('index.html', items=items, search_query=search_query)

@app.route('/users')
def users():
    all_users = User.query.all()
    # 将用户分为在线和离线两组
    online_users = [user for user in all_users if user.is_online()]
    offline_users = [user for user in all_users if not user.is_online()]
    return render_template('users.html', online_users=online_users, offline_users=offline_users)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    # 获取在售物品
    active_items = Item.query.filter_by(user_id=user_id, is_sold=False).order_by(Item.created_at.desc()).all()
    # 获取已售物品（如果允许查看）
    sold_items = []
    if user.show_sold_items or (session.get('user_id') == user_id):
        sold_items = Item.query.filter_by(user_id=user_id, is_sold=True).order_by(Item.created_at.desc()).all()
    return render_template('user_profile.html', user=user, active_items=active_items, sold_items=sold_items)

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
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('该用户名已被使用，请选择其他用户名')
            return redirect(url_for('login'))
        else:
            new_user = User(username=username)
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session.permanent = True  # 设置session为永久性
            flash('登录成功！')
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('已退出登录')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        flash('请先登录')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        
        if 'image' not in request.files:
            flash('没有选择图片')
            return redirect(request.url)
            
        file = request.files['image']
        if file.filename == '':
            flash('没有选择图片')
            return redirect(request.url)
            
        if file:
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            new_item = Item(
                title=title,
                description=description,
                price=price,
                category=category,
                image_path=f"uploads/{filename}",
                user_id=session['user_id']
            )
            
            db.session.add(new_item)
            db.session.commit()
            
            flash('物品上传成功！')
            return redirect(url_for('index'))
            
    return render_template('upload.html')

@app.route('/reserve/<int:item_id>')
def reserve(item_id):
    if 'user_id' not in session:
        flash('请先登录')
        return redirect(url_for('login'))
        
    item = Item.query.get_or_404(item_id)
    if not item.is_reserved:
        item.is_reserved = True
        db.session.commit()
        flash('预定成功！')
    else:
        flash('该物品已被预定')
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

if __name__ == '__main__':
    app.run(debug=True) 