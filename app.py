from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ctf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==================== Models ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    score = db.Column(db.Integer, default=0)

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.Text, nullable=False)
    flag = db.Column(db.String(200), nullable=False)
    points = db.Column(db.Integer, nullable=False)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    __table_args__ = (db.UniqueConstraint('user_id', 'challenge_id', name='unique_user_challenge'),)

# ==================== Routes ====================
from flask import Flask, render_template

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="اسم المستخدم موجود بالفعل. الرجاء اختيار اسم آخر.")

        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    challenges = Challenge.query.all()
    
    # استعلام لمعرفة التحديات التي حلها المستخدم
    solved_challenges = db.session.query(Submission.challenge_id).filter_by(user_id=user_id).all()
    solved_ids = {challenge_id for (challenge_id,) in solved_challenges}

    return render_template('dashboard.html', challenges=challenges, solved_ids=solved_ids)


@app.route('/submit_flag/<int:challenge_id>', methods=['POST'])
def submit_flag(challenge_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    challenge = Challenge.query.get(challenge_id)
    submitted_flag = request.form['flag']

    existing = Submission.query.filter_by(user_id=user_id, challenge_id=challenge_id).first()
    if existing:
        flash('لقد قمت بحل هذا التحدي مسبقًا!', 'warning')
        return redirect(url_for('dashboard'))

    if submitted_flag == challenge.flag:
        user.score += challenge.points
        submission = Submission(user_id=user_id, challenge_id=challenge_id)
        db.session.add(submission)
        db.session.commit()
        flash('إجابة صحيحة! تم تحديث رصيدك.', 'success')
    else:
        flash('إجابة خاطئة، حاول مرة أخرى.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form['password']
        if password == 'admin123':
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin'))


    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        description = request.form['description']
        flag = request.form['flag']
        points = int(request.form['points'])

        challenge = Challenge(title=title, category=category, description=description, flag=flag, points=points)
        db.session.add(challenge)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    challenges = Challenge.query.all()
    users = User.query.order_by(User.score.desc()).all()
    return render_template('admin_dashboard.html', challenges=challenges, users=users)

@app.route('/delete_challenge/<int:challenge_id>', methods=['POST'])
def delete_challenge(challenge_id):
    if not session.get('admin'):
        return redirect(url_for('admin'))

    challenge = Challenge.query.get_or_404(challenge_id)
    db.session.delete(challenge)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('تم حذف المستخدم بنجاح', 'success')
    else:
        flash('المستخدم غير موجود', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/scoreboard')
def scoreboard():
    users = User.query.order_by(User.score.desc()).all()
    return render_template('scoreboard.html', users=users)

# ==================== Main ====================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    # ... كود تطبيق Flask بالكامل ...

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

