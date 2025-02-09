import datetime
import logging
import os
from logging.handlers import RotatingFileHandler


from flask import jsonify, request


from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from sqlalchemy import create_engine

from flask import Flask

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)




# Sqlalchemy, Jwt, and, Bcrypt Manage Configs
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://<user_name>:<password>@<host>/<db_name>"
app.config['JWT_SECRET_KEY'] = '<Jwt_secret>'  # This can be Changed for different Environments


sql_alchemy = SQLAlchemy()
bcrypt_manager = Bcrypt()
jwt_manager = JWTManager()

sql_alchemy.init_app(app)
bcrypt_manager.init_app(app)
jwt_manager.init_app(app)

Base = declarative_base()




# File Logs Setup

info_log_file: str = "logs/info.log"   # Set The log File(This will create the log directory and info.log file there
os.makedirs(os.path.dirname(info_log_file), exist_ok=True) # Create the log directory if It Doesn't exists
info_logger = logging.getLogger("Info Logs")
info_logger.setLevel(logging.INFO)
request_log_handler = RotatingFileHandler(info_log_file, maxBytes=52428800, backupCount=3)




# Method To Hash password with Bcrypt manager
def pwd_hash(password):
    return bcrypt_manager.generate_password_hash(password).decode('utf-8')


# Method To Validate password with Bcrypt manager
def check_pwd(saved_pwd, password):
    return bcrypt_manager.check_password_hash(saved_pwd, password)

# Method To generate JWT Token
def generate_token(identity, additional_claims=None):
    return create_access_token(identity=identity, additional_claims=additional_claims)



class Users(Base):
    """
    Create Users Table Model
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    full_name = Column(String(200))
    username = Column(String(200), nullable=False)
    email = Column(String(200))
    password = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.now())
    updated_at = Column(DateTime, default=datetime.datetime.now())


class Departments(Base):
    """
       Create Departments Table Model
    """

    __tablename__ = 'departments'

    id = Column(Integer, primary_key=True, autoincrement=True)
    department_name = Column(String(200), nullable=False)
    submitted_by = ForeignKey(column=Users.id, ondelete="CASCADE")
    updated_at = Column(DateTime, default=datetime.datetime.now())


class Students(Base):
    """
    Create Students Table Model
    """
    __tablename__ = 'students'

    id = Column(Integer, primary_key=True, autoincrement=True)
    full_name = Column(String(200), nullable=False)
    department_id = ForeignKey(column=Departments.id, ondelete="CASCADE")
    submitted_by = ForeignKey(column=Users.id, ondelete="CASCADE")
    class_name = Column(String(200), nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.now())


class Courses(Base):
    """
     Create Courses Table Model
    """
    __tablename__ = 'courses'

    id = Column(Integer, primary_key=True, autoincrement=True)
    course_name = Column(String(200), nullable=False)
    department_id = ForeignKey(column=Departments.id, ondelete="CASCADE")
    class_name = Column(String(200), nullable=False)
    lecture_hours = Column(String(200), nullable=False)
    submitted_by = Column(String(200), nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.now())


class AttendanceLog(Base):
    """
         Create AttendanceLog Table Model
    """

    __tablename__ = 'attendance_log'

    id = Column(Integer, primary_key=True, autoincrement=True)
    student_id = ForeignKey(column=Users.id, ondelete="DELETE")
    course_id = ForeignKey(column=Courses.id, ondelete="CASCADE")
    present = Column(String(200), nullable=False)
    submitted_by = Column(String(200), nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.now())



def create_user_on_app_run():
    with app.app_context():
        try:
            users = sql_alchemy.session.query(Users).all()
            if not users:
                data = {'username': 'admin123', 'password': 'Admin@123'}
                hashed_password = pwd_hash(data.pop('password'))
                user_obj = Users(username='admin123', password=hashed_password)
                sql_alchemy.session.add(user_obj)
                sql_alchemy.session.commit()
                user_data = {'user_id': user_obj.id, 'username': user_obj.username, 'password': user_obj.password}
                info_logger.info(f'First User Registered : User Data - {user_data} - Created at: {datetime.datetime.now()}')
        except Exception as e:
            info_logger.info(f'Error Occurred : {str(e)} - Created at: {datetime.datetime.now()}')
            return jsonify({'message': 'Something Went Wrong'}), 401

@app.route(rule='/register', methods=['POST'])
def register():
    with app.app_context():
        try:
            data = request.get_json()
            hashed_password = pwd_hash(data.pop('password'))
            user_obj = Users(**data, password=hashed_password)
            sql_alchemy.session.add(user_obj)
            sql_alchemy.session.commit()
            user_data = {'user_id': user_obj.id, 'username': user_obj.username}
            info_logger.info(f'User Registered :  User Data - {user_data} - Create at: {datetime.datetime.now()}')
            return jsonify({'message': 'User created successfully', "data": user_data}), 201
        except Exception as e:
            info_logger.info(f'Error Occurred : {str(e)} - Create at: {datetime.datetime.now()}')
            return jsonify({'message': 'Somthing Went Wrong'}), 401


@app.route(rule='/login', methods=['POST'])
def login():
    with app.app_context():
        try:
            data = request.get_json()
            password = data.get('password')
            user_data = sql_alchemy.session.query(Users).filter_by(username=data.get('username')).first()
            if not user_data or not check_pwd(user_data.password, password):
                user_data = 'invalid_user'
            if user_data != 'invalid_user':
                additional_claims = {'username': user_data.username}
                return jsonify({"access_token": generate_token(user_data.id, additional_claims)}), 200
            return jsonify({'message': 'Invalid credentials'}), 401
        except Exception as e:
            info_logger.info(f'Error Occurred : {str(e)} - Create at: {datetime.datetime.now()}')
        return jsonify({'message': 'Somthing Went Wrong'}), 401


@app.route(rule='/courses')
@jwt_required()
def courses(request):
    """
    Route To get the available courses
    :param request:
    :return:
    """
    with app.app_context():
        try:
            cources_data = sql_alchemy.session.query(Courses).all()
            data = []
            for item in cources_data:
                data.append({'course_id': item.id,
                             'coursename': item.course_name})
            return jsonify({'message': 'User created successfully', "data": data}), 200
        except Exception as e:
            return jsonify({'message': 'Somthing Went Wrong'}), 401





if __name__=="__main__":
    engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"])
    Base.metadata.create_all(bind=engine)
    create_user_on_app_run()
    app.run()
