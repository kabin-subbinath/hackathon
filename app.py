import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import qrcode
import io
import base64

# --- App Configuration ---
app = Flask(__name__)

instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
os.makedirs(instance_path, exist_ok=True)

app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(instance_path, 'database.db')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    roll_no = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    parent_contact = db.Column(db.String(15))
    student_mobile = db.Column(db.String(15))
    college_reg_no = db.Column(db.String(20))
    department = db.Column(db.String(50))
    year = db.Column(db.String(10))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    from_date = db.Column(db.DateTime, nullable=False)
    to_date = db.Column(db.DateTime, nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    returned = db.Column(db.Boolean, default=False)
    qr_code = db.Column(db.Text)
    student_name = db.Column(db.String(100))
    college_reg_no = db.Column(db.String(20))
    department = db.Column(db.String(50))
    year = db.Column(db.String(10))
    student_mobile = db.Column(db.String(15))
    parent_contact = db.Column(db.String(15))
    student = db.relationship('User', backref=db.backref('leave_requests', lazy=True))

class GatePass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    out_time = db.Column(db.DateTime, nullable=False)
    expected_return_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    returned = db.Column(db.Boolean, default=False)
    qr_code = db.Column(db.Text)
    student_name = db.Column(db.String(100))
    college_reg_no = db.Column(db.String(20))
    department = db.Column(db.String(50))
    year = db.Column(db.String(10))
    student_mobile = db.Column(db.String(15))
    parent_contact = db.Column(db.String(15))
    student = db.relationship('User', backref=db.backref('gate_passes', lazy=True))

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, nullable=False)
    request_type = db.Column(db.String(20), nullable=False)
    student_reg_no = db.Column(db.String(20))
    student_name = db.Column(db.String(100))
    student_mobile = db.Column(db.String(15))
    parent_mobile = db.Column(db.String(15))
    out_time = db.Column(db.DateTime, nullable=True)
    in_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20)) # 'Approved', 'Out', or 'Returned'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_str}"

@app.route("/")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        target_url = f"{current_user.role}_dashboard"
        return redirect(url_for(target_url))
    if request.method == 'POST':
        roll_no = request.form.get('roll_no')
        password = request.form.get('password')
        user = User.query.filter_by(roll_no=roll_no).first()
        if user and user.verify_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            target_url = f"{user.role}_dashboard"
            return redirect(url_for(target_url))
        else:
            flash('Invalid Roll No or Password.', 'danger')
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/student/dashboard")
@login_required
def student_dashboard():
    if current_user.role != 'student': return redirect(url_for('login'))
    leave_requests = LeaveRequest.query.filter_by(student_id=current_user.id).order_by(LeaveRequest.id.desc()).all()
    gate_passes = GatePass.query.filter_by(student_id=current_user.id).order_by(GatePass.id.desc()).all()
    return render_template('student_dashboard.html', leave_requests=leave_requests, gate_passes=gate_passes)

@app.route("/student/request_leave", methods=['POST'])
@login_required
def request_leave():
    form = request.form
    new_leave = LeaveRequest(
        student_id=current_user.id,
        destination=form.get('destination'),
        reason=form.get('reason'),
        from_date=datetime.strptime(form.get('from_date'), '%Y-%m-%dT%H:%M'),
        to_date=datetime.strptime(form.get('to_date'), '%Y-%m-%dT%H:%M'),
        student_name=form.get('student_name'),
        college_reg_no=form.get('college_reg_no'),
        department=form.get('department'),
        year=form.get('year'),
        student_mobile=form.get('student_mobile'),
        parent_contact=form.get('parent_contact')
    )
    db.session.add(new_leave)
    db.session.commit()
    flash('Leave request submitted successfully!', 'success')
    return redirect(url_for('student_dashboard'))

@app.route("/student/request_gatepass", methods=['POST'])
@login_required
def request_gatepass():
    form = request.form
    new_pass = GatePass(
        student_id=current_user.id,
        out_time=datetime.strptime(form.get('out_time'), '%Y-%m-%dT%H:%M'),
        expected_return_time=datetime.strptime(form.get('return_time'), '%Y-%m-%dT%H:%M'),
        student_name=form.get('student_name'),
        college_reg_no=form.get('college_reg_no'),
        department=form.get('department'),
        year=form.get('year'),
        student_mobile=form.get('student_mobile'),
        parent_contact=form.get('parent_contact')
    )
    db.session.add(new_pass)
    db.session.commit()
    flash('Gate pass request submitted successfully!', 'success')
    return redirect(url_for('student_dashboard'))

@app.route("/warden/dashboard")
@login_required
def warden_dashboard():
    if current_user.role != 'warden': return redirect(url_for('login'))
    pending_leaves = LeaveRequest.query.filter_by(status='Pending').all()
    pending_passes = GatePass.query.filter_by(status='Pending').all()
    scan_logs = ScanLog.query.order_by(ScanLog.id.desc()).all()
    return render_template('warden_dashboard.html',
                           pending_leaves=pending_leaves,
                           pending_passes=pending_passes,
                           scan_logs=scan_logs)

@app.route("/warden/leave/<int:request_id>/<action>", methods=['POST'])
@login_required
def manage_leave(request_id, action):
    leave = LeaveRequest.query.get_or_404(request_id)
    if action == 'approve':
        leave.status = 'Approved'
        qr_data = f"Leave|{leave.id}"
        leave.qr_code = generate_qr_code(qr_data)
        new_log = ScanLog(
            request_id=leave.id, request_type='Leave', student_reg_no=leave.college_reg_no,
            student_name=leave.student_name, student_mobile=leave.student_mobile,
            parent_mobile=leave.parent_contact, status='Approved'
        )
        db.session.add(new_log)
    elif action == 'reject':
        leave.status = 'Rejected'
    db.session.commit()
    return redirect(url_for('warden_dashboard'))

@app.route("/warden/gatepass/<int:pass_id>/<action>", methods=['POST'])
@login_required
def manage_gatepass(pass_id, action):
    gate_pass = GatePass.query.get_or_404(pass_id)
    if action == 'approve':
        gate_pass.status = 'Approved'
        qr_data = f"GatePass|{gate_pass.id}"
        gate_pass.qr_code = generate_qr_code(qr_data)
        new_log = ScanLog(
            request_id=gate_pass.id, request_type='GatePass', student_reg_no=gate_pass.college_reg_no,
            student_name=gate_pass.student_name, student_mobile=gate_pass.student_mobile,
            parent_mobile=gate_pass.parent_contact, status='Approved'
        )
        db.session.add(new_log)
    elif action == 'reject':
        gate_pass.status = 'Rejected'
    db.session.commit()
    return redirect(url_for('warden_dashboard'))

@app.route("/security/dashboard")
@login_required
def security_dashboard():
    if current_user.role != 'security': return redirect(url_for('login'))
    scan_logs = ScanLog.query.filter(ScanLog.status.in_(['Out', 'Returned'])).order_by(ScanLog.id.desc()).all()
    return render_template('security_dashboard.html', scan_logs=scan_logs)

@app.route('/api/scan_qr', methods=['POST'])
@login_required
def scan_qr():
    if current_user.role != 'security': return jsonify({'error': 'Unauthorized access'}), 403
    data = request.get_json()
    qr_content = data.get('qr_content')
    try:
        type, id_str = qr_content.split('|')
        id = int(id_str)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid QR Code format.'}), 400

    log_entry = ScanLog.query.filter_by(request_type=type, request_id=id).first()
    if not log_entry: return jsonify({'error': 'This QR code is not valid or has not been approved.'}), 404

    if log_entry.status == 'Approved':
        log_entry.out_time = datetime.now()
        log_entry.status = 'Out'
        db.session.commit()
        return jsonify({
            'status_message': 'Student Exiting', 'student_name': log_entry.student_name,
            'reg_no': log_entry.student_reg_no, 'out_time': log_entry.out_time.strftime('%d %b, %I:%M %p')
        })
    elif log_entry.status == 'Out':
        log_entry.in_time = datetime.now()
        log_entry.status = 'Returned'
        Model = LeaveRequest if type == 'Leave' else GatePass
        req = Model.query.get(id)
        if req: req.returned = True
        db.session.commit()
        return jsonify({
            'status_message': 'Student Returned', 'student_name': log_entry.student_name,
            'reg_no': log_entry.student_reg_no, 'out_time': log_entry.out_time.strftime('%d %b, %I:%M %p'),
            'in_time': log_entry.in_time.strftime('%d %b, %I:%M %p')
        })
    elif log_entry.status == 'Returned':
        return jsonify({'error': 'This QR code has already been used for return.'}), 400
    return jsonify({'error': 'Invalid request state.'}), 400

def setup_database(app):
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(roll_no='warden01').first():
            db.session.add(User(roll_no='warden01', name='Head Warden', role='warden', password='password123'))
        if not User.query.filter_by(roll_no='security01').first():
            db.session.add(User(roll_no='security01', name='Main Gate Security', role='security', password='password123'))
        if not User.query.filter_by(roll_no='STU001').first():
            db.session.add(User(roll_no='STU001', name='John Doe', role='student', password='password123'))
        db.session.commit()


# --- THIS IS THE FIX ---
# Call setup_database() when the app starts, outside the main block.
# This ensures tables are created when deployed on a server like Render.
with app.app_context():
    setup_database(app)


# The main block below is now only for running the app on your local computer.
# The production server (Gunicorn) will ignore this.
if __name__ == '__main__':
    # For local development, you can still use the HTTPS context for your camera
    # app.run(debug=True, ssl_context='adhoc', host='0.0.0.0')
    
    # Or run it simply with HTTP
    app.run(debug=True, host='0.0.0.0')