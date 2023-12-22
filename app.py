from flask import Flask, request
from flask_restful import Api, Resource, marshal_with, fields
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import os

#################################
## INIT #########################
#################################

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress a warning
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

#################################
## MODELS #######################
#################################

# Model for tasks associated with users
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return self.name

# Model for user authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
    
# Task fields
taskFields = {
    'id':fields.Integer,
    'name':fields.String,
    #'user_id': fields.String,
 }

# Items class
class Items(Resource):
    @jwt_required()
    @marshal_with(taskFields)
    def get(self):
        current_user = get_jwt_identity()
        tasks = Task.query.filter_by(user_id=current_user).all()
        return tasks
     # Create Task
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        data = request.json
        if 'name' not in data:
            return {'message': 'Name is required'}, 400
        task = Task(name=data['name'], user_id=current_user)
        db.session.add(task) # Add to db
        db.session.commit() # Commit changes
        return { 'message': 'Task created' }, 201
    
# Individual item class
class Item(Resource):
    
    @jwt_required()
    @marshal_with(taskFields)
    def get(self, pk):
        user_id = get_jwt_identity()
        task = Task.query.get_or_404(pk)
        if task.user_id != user_id:
            return {'message': 'Unauthorized'}, 401
        return task
    # Update item
    @jwt_required()
    @marshal_with(taskFields)
    def put(self, pk):
        user_id = get_jwt_identity()
        data = request.json
        task = Task.query.get_or_404(pk)
        if task.user_id != user_id:
            return {'message': 'Unauthorized'}, 401
        task.name = data['name']
        db.session.commit()
        return task
    # Delete item
    @jwt_required()
    def delete(self, pk):
        user_id = get_jwt_identity()
        task = Task.query.get_or_404(pk)
        if task.user_id != user_id:
            return {'message': 'Unauthorized'}, 401
        db.session.delete(task)
        db.session.commit()
        return { 'message': 'Item deleted'}
    
# Resource for user registration
class UserRegistration(Resource):
    def post(self):
        data = request.json
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'message': 'Username and password are required'}, 400

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            return {'message': 'Username already exists'}, 400

        # Create a new user
        new_user = User(username=username, password=password)
        
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully'}, 201

# Resource for user login
class UserLogin(Resource):
    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'message': 'Username and password are required'}, 400
    
        # Check if the username and password are valid
        user = User.query.filter_by(username=username).first()
        
        if user is None:
            return {'message': 'Invalid credentials'}, 401
    
        is_pwd_valid = user.check_password(password)

        if is_pwd_valid:
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid credentials'}, 401

##########################################################
# Add base resource (using class instead of ) ############
##########################################################


# Tasks
api.add_resource(Items, '/tasks')
api.add_resource(Item, '/tasks/<int:pk>')

# Auth
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')

# Run server
if __name__ == '__main__':
    app.run(debug=True)