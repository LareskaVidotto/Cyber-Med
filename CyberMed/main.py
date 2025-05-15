from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_warning_alerts(user):
    # Enviar email
    try:
        sender_email = os.getenv('SMTP_EMAIL', 'seu-sistema@exemplo.com')
        smtp_password = os.getenv('SMTP_PASSWORD', '')
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = user.email
        msg['Subject'] = "ALERTA - Conta Bloqueada"

        body = f"""
        Prezado(a) usuário(a),

        Sua conta foi bloqueada após 3 tentativas incorretas de login.
        Para desbloquear, use a pergunta de segurança no sistema.

        Clínica: {user.clinic_name}
        Usuário: {user.username}
        Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

        Se não foi você, entre em contato com o administrador.
        """

        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(smtp_server, 587) as server:
            server.starttls()
            server.login(sender_email, smtp_password)
            server.send_message(msg)

    except Exception as e:
        print(f"Erro ao enviar email: {e}")

    # Enviar SMS (usando Twilio como exemplo)
    try:
        account_sid = os.getenv('TWILIO_ACCOUNT_SID')
        auth_token = os.getenv('TWILIO_AUTH_TOKEN')
        from_number = os.getenv('TWILIO_FROM_NUMBER')

        if account_sid and auth_token and from_number and user.phone:
            from twilio.rest import Client
            client = Client(account_sid, auth_token)

            message = client.messages.create(
                body=f"ALERTA: Sua conta na {user.clinic_name} foi bloqueada após 3 tentativas incorretas de login.",
                from_=from_number,
                to=user.phone
            )
    except Exception as e:
        print(f"Erro ao enviar SMS: {e}")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clinic.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    is_blocked = db.Column(db.Boolean, default=False)
    security_question = db.Column(db.String(200), nullable=False)
    security_answer = db.Column(db.String(200), nullable=False)
    clinic_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    document = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    appointments = db.relationship('Appointment', backref='patient', lazy=True)
    records = db.relationship('MedicalRecord', backref='patient', lazy=True)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    notes = db.Column(db.Text)
    doctor = db.Column(db.String(100))
    created_by = db.Column(db.String(100))
    time_slot = db.Column(db.String(10))
    confirmed = db.Column(db.Boolean, default=False)
    confirmation_date = db.Column(db.DateTime)

class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    record_date = db.Column(db.DateTime, default=datetime.utcnow)
    diagnosis = db.Column(db.Text)
    treatment = db.Column(db.Text)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    access_date = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe', 'error')
            return redirect(url_for('register'))

        user = User(
            username=username,
            email=request.form['email'],
            password_hash=generate_password_hash(password),
            clinic_name=request.form['clinic_name'],
            address=request.form['address'],
            phone=request.form['phone'],
            security_question="Qual é o nome do seu primeiro animal de estimação?",
            security_answer=request.form['security_answer']
        )
        db.session.add(user)
        db.session.commit()
        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Registrar tentativa de login antes de qualquer validação
        log = LoginLog(
            username=request.form.get('username', ''),
            ip_address=request.remote_addr,
            success=False
        )
        db.session.add(log)
        db.session.commit()

        user = User.query.filter_by(username=request.form['username']).first()

        if not user:
            log.success = False
            db.session.add(log)
            db.session.commit()
            flash('Usuário não encontrado', 'error')
            return render_template('login.html')

        if user.is_blocked:
            if 'security_answer' in request.form:
                if user.security_answer.lower() == request.form['security_answer'].lower():
                    user.is_blocked = False
                    user.failed_attempts = 0
                    db.session.commit()
                    flash('Conta desbloqueada. Faça login novamente.', 'success')
                else:
                    flash('Resposta incorreta.', 'error')
            return render_template('login.html', show_security=True, username=user.username)

        if 'password' in request.form:
            if check_password_hash(user.password_hash, request.form['password']):
                if user.failed_attempts >= 3:
                    user.is_blocked = True
                    db.session.commit()
                    send_warning_alerts(user)
                    flash('Conta bloqueada após 3 tentativas. Um alerta foi enviado.', 'error')
                    return render_template('login.html', show_security=True, username=user.username)

                login_user(user)
                user.failed_attempts = 0
                log.success = True
                db.session.commit()
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('appointments'))
            else:
                user.failed_attempts += 1
                db.session.commit()
                flash('Senha incorreta. Tentativa registrada.', 'error')

    return render_template('login.html')

@app.route('/appointments')
@login_required
def appointments():
    appointments = Appointment.query.all()
    return render_template('appointments.html', appointments=appointments)

@app.route('/add_appointment', methods=['GET', 'POST'])
@login_required
def add_appointment():
    patients = Patient.query.order_by(Patient.name).all()
    if request.method == 'POST':
        patient = Patient.query.get(request.form['patient_id'])

        # Criar agendamento
        appointment = Appointment(
            patient=patient,
            date=datetime.strptime(f"{request.form['date']} {request.form['time_slot']}", '%Y-%m-%d %H:%M'),
            notes=request.form['notes'],
            doctor=request.form['doctor'],
            created_by=current_user.username,
            time_slot=request.form['time_slot']
        )
        db.session.add(appointment)
        db.session.commit()
        flash('Agendamento criado com sucesso!', 'success')
        return redirect(url_for('appointments'))
    return render_template('add_appointment.html', patients=patients)

@app.route('/records', methods=['GET'])
@login_required
def records():
    records = MedicalRecord.query.order_by(MedicalRecord.record_date.desc()).all()
    patients = Patient.query.order_by(Patient.name).all()
    return render_template('records.html', records=records, patients=patients)

@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if request.method == 'POST':
        patient = Patient(
            name=request.form['name'],
            age=request.form['age'],
            document=request.form['document'],
            address=request.form['address'],
            phone=request.form['phone']
        )
        db.session.add(patient)
        db.session.commit()
        flash('Paciente cadastrado com sucesso!', 'success')
        return redirect(url_for('patients'))
    return render_template('add_patient.html')

@app.route('/patients')
@login_required
def patients():
    patients = Patient.query.order_by(Patient.name).all()
    return render_template('patients.html', patients=patients)

@app.route('/patient/<int:id>')
@login_required
def patient_details(id):
    patient = Patient.query.get_or_404(id)
    return render_template('patient_details.html', patient=patient)

@app.route('/confirm_appointment/<int:id>')
@login_required
def confirm_appointment(id):
    appointment = Appointment.query.get_or_404(id)
    appointment.confirmed = True
    appointment.confirmation_date = datetime.utcnow()
    db.session.commit()
    flash('Consulta confirmada com sucesso!', 'success')
    return redirect(url_for('appointments'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso.', 'success')
    return redirect(url_for('login'))

@app.route('/edit_appointment/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_appointment(id):
    appointment = Appointment.query.get_or_404(id)
    if request.method == 'POST':
        appointment.patient_name = request.form['patient_name']
        appointment.date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
        appointment.notes = request.form['notes']
        appointment.doctor = request.form['doctor']
        appointment.time_slot = request.form['time_slot']
        db.session.commit()
        flash('Agendamento atualizado com sucesso!', 'success')
        return redirect(url_for('appointments'))
    return render_template('add_appointment.html', appointment=appointment)

@app.route('/delete_appointment/<int:id>')
@login_required
def delete_appointment(id):
    appointment = Appointment.query.get_or_404(id)
    db.session.delete(appointment)
    db.session.commit()
    flash('Agendamento excluído com sucesso!', 'success')
    return redirect(url_for('appointments'))

@app.route('/edit_record/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_record(id):
    record = MedicalRecord.query.get_or_404(id)
    if request.method == 'POST':
        record.patient_name = request.form['patient_name']
        record.diagnosis = request.form['diagnosis']
        record.treatment = request.form['treatment']
        db.session.commit()
        flash('Prontuário atualizado com sucesso!', 'success')
        return redirect(url_for('records'))
    return render_template('records.html', edit_record=record)

@app.route('/delete_record/<int:id>')
@login_required
def delete_record(id):
    record = MedicalRecord.query.get_or_404(id)
    db.session.delete(record)
    db.session.commit()
    flash('Prontuário excluído com sucesso!', 'success')
    return redirect(url_for('records'))

@app.route('/add_record', methods=['POST'])
@login_required
def add_record():
    patient = Patient.query.get(request.form['patient_id'])
    if patient:
        record = MedicalRecord(
            patient=patient,
            diagnosis=request.form['diagnosis'],
            treatment=request.form['treatment']
        )
        db.session.add(record)
        db.session.commit()
        flash('Prontuário adicionado com sucesso!', 'success')
    else:
        flash('Paciente não encontrado', 'error')
    return redirect(url_for('records'))

@app.route('/access_logs')
@login_required
def access_logs():
    logs = LoginLog.query.order_by(LoginLog.access_date.desc()).all()
    return render_template('access_logs.html', logs=logs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)