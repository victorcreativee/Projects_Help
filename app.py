from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)

roles = [('admin', 'Admin'), ('lecturer', 'Lecturer'), ('student', 'Student')]

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}')"

# File upload model
class FileUpload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(25), db.ForeignKey('user.username'), nullable=False)

    def __repr__(self):
        return f"FileUpload('{self.filename}', '{self.description}', '{self.username}')"

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    role = SelectField('Role', choices=roles, validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = StringField('Upload PDF File', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    submit = SubmitField('Upload')

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'username' not in session or session['role'] != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['username'] = user.username
            session['role'] = user.role
            print(f"Login successful: {user.username}, Role: {user.role}")  # Debug log
            return redirect(url_for('dashboard'))
        else:
            print("Login failed.")  # Debug log
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        role = session['role']
        print(f"Redirecting {username} with role {role}")  # Debug log
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'student':
            return redirect(url_for('student_dashboard'))
        elif role == 'lecturer':
            return redirect(url_for('lecturer_dashboard'))
        flash('Role not recognized', 'danger')
        return redirect(url_for('home'))
    print("User not in session.")  # Debug log
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@role_required('admin')
def admin_dashboard():
    if 'username' in session:
        username = session['username']
        users = User.query.all()
        uploads = FileUpload.query.all()
        return render_template('admin_dashboard.html', username=username, users=users, uploads=uploads)
    return redirect(url_for('login'))

@app.route('/student_dashboard')
@role_required('student')
def student_dashboard():
    if 'username' in session:
        username = session['username']
        search_query = request.args.get('search', '').lower()
        lecturer_uploads = db.session.query(FileUpload, User).join(User).filter(
            User.role == 'lecturer', 
            (FileUpload.filename.ilike(f"%{search_query}%") | FileUpload.description.ilike(f"%{search_query}%"))
        ).all()
        
        uploads = [
            {'filename': upload.filename, 
             'description': upload.description, 
             'username': user.username} 
            for upload, user in lecturer_uploads
        ]
        
        return render_template('student_dashboard.html', username=username, uploads=uploads)
    return redirect(url_for('login'))


@app.route('/lecturer_dashboard')
@role_required('lecturer')
def lecturer_dashboard():
    if 'username' in session:
        username = session['username']
        user_uploads = FileUpload.query.filter_by(username=username).all()
        return render_template('lecturer_dashboard.html', username=username, uploads=user_uploads)
    return redirect(url_for('login'))

@app.route('/create_user', methods=['GET', 'POST'])
@role_required('admin')
def create_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('register.html', form=form)

@app.route('/edit_user/<username>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user.username = form.username.data
        user.role = form.role.data
        if form.password.data:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    form.username.data = user.username
    form.role.data = user.role
    return render_template('edit_user.html', form=form, username=username)

@app.route('/delete_user/<username>', methods=['POST'])
@role_required('admin')
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
@role_required('lecturer')
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        file = request.files.get('file')
        if file and file.filename:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            upload = FileUpload(filename=file.filename, description=form.description.data, username=session['username'])
            db.session.add(upload)
            db.session.commit()
            flash('File uploaded successfully!')
            return redirect(url_for('lecturer_dashboard'))
    return render_template('upload.html', form=form)

@app.route('/view_uploads')
@role_required('lecturer')
def view_uploads():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('view_uploads.html', files=files)

@app.route('/upload/<filename>/edit', methods=['GET', 'POST'])
@role_required('lecturer')
def edit_upload(filename):
    upload = FileUpload.query.filter_by(filename=filename).first()
    if request.method == 'POST':
        new_filename = request.form.get('new_filename')
        if new_filename:
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            new_file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            os.rename(old_file_path, new_file_path)
            upload.filename = new_filename
            db.session.commit()
            flash('File renamed successfully!')
            return redirect(url_for('lecturer_dashboard'))
    return render_template('edit_upload.html', filename=filename)

@app.route('/upload/<filename>/delete', methods=['POST'])
@role_required('lecturer')
def delete_upload(filename):
    upload = FileUpload.query.filter_by(filename=filename).first()
    if upload:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(upload)
        db.session.commit()
        flash('File deleted successfully!')
    return redirect(url_for('lecturer_dashboard'))

@app.route('/admin_only')
@role_required('admin')
def admin_only():
    return render_template('admin_only.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8000, debug=True)

# @app.route('/admin_only')
# @role_required('admin')
# def admin_only():
#     return render_template('admin_only.html')

# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     session.pop('role', None)
#     return redirect(url_for('home'))
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8000, debug=True)
