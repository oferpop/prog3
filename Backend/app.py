from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)  # Enable CORS for all routes
api = Api(app)

# JWT Setup
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with your actual secret key
jwt = JWTManager(app)

# SQLite Setup
db_file_path = 'sqlite:///your_database_file.db'  # Replace with the path to your SQLite database file
app.config['SQLALCHEMY_DATABASE_URI'] = db_file_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
db = SQLAlchemy(app)

# Define your SQLAlchemy models here
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer)
    type = db.Column(db.Integer, nullable=False)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    loan_date = db.Column(db.DateTime, default=datetime.utcnow)
    return_date = db.Column(db.DateTime)

# Create the database tables based on the models
with app.app_context():
    db.create_all()

# Function to add initial books to the database
def add_initial_books():
    if Book.query.count() == 0:
        books_to_add = [
            Book(name="Book One", author="Author A", year_published=2001, type=1),
            Book(name="Book Two", author="Author B", year_published=2002, type=2),
            Book(name="Book Three", author="Author C", year_published=2003, type=3)
        ]

        db.session.bulk_save_objects(books_to_add)
        db.session.commit()
        print("Initial books added to the database.")
    else:
        print("Books already exist in the database.")

# Function to add test customers and loans to the database
def add_test_data():
    if Customer.query.count() == 0:
        customers_to_add = [
            Customer(name="Alice", city="City A", age=30, gender="Female"),
            Customer(name="Bob", city="City B", age=25, gender="Male"),
            Customer(name="Charlie", city="City C", age=35, gender="Male")
        ]

        db.session.bulk_save_objects(customers_to_add)
        db.session.commit()
        print("Customers added to the database.")
    else:
        print("Customers already exist in the database.")

    if Loan.query.count() == 0 and Book.query.count() >= 3:
        books = Book.query.all()
        customers = Customer.query.all()
        if books and customers:
            loans_to_add = [
                Loan(cust_id=customers[0].id, book_id=books[0].id, loan_date=datetime.utcnow()),
                Loan(cust_id=customers[1].id, book_id=books[1].id, loan_date=datetime.utcnow()),
                Loan(cust_id=customers[2].id, book_id=books[2].id, loan_date=datetime.utcnow())
            ]

            db.session.bulk_save_objects(loans_to_add)
            db.session.commit()
            print("Loans added to the database.")
        else:
            print("Insufficient data to create loans.")
    else:
        print("Loans already exist in the database.")

UPLOAD_FOLDER = 'backend/static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class Hello(Resource):
    def get(self):
        return send_from_directory('../frontend', 'index.html')

class UploadImage(Resource):
    def post(self):
        if 'file' not in request.files:
            return {"error": "No file part"}, 400

        file = request.files['file']
        if file.filename == '':
            return {"error": "No selected file"}, 400

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return {"message": "File uploaded successfully", "filename": filename}, 200

class ListImages(Resource):
    def get(self):
        images = os.listdir(app.config['UPLOAD_FOLDER'])
        image_urls = [f"http://127.0.0.1:5000/static/uploads/{image}" for image in images]
        return {"images": image_urls}

api.add_resource(Hello, '/')
api.add_resource(UploadImage, '/upload')
api.add_resource(ListImages, '/images')


@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/rent_book/<int:book_id>', methods=['POST'])
def rent_book(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({"message": "Book not found"}), 404

    # Check if the book is already on loan
    loan = Loan.query.filter_by(book_id=book.id, return_date=None).first()
    if loan:
        return jsonify({"message": "Book already rented", "return_date": loan.return_date}), 400

    # Create a new loan
    new_loan = Loan(cust_id=1, book_id=book.id)  # Assuming a default customer for simplicity
    db.session.add(new_loan)
    db.session.commit()
    return jsonify({"message": "Book rented successfully"})

@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    current_user = get_jwt_identity()
    books = Book.query.all()
    book_details = []

    for book in books:
        # Check if the book is already on loan
        loan = Loan.query.filter_by(book_id=book.id, return_date=None).first()
        if loan:
            availability = "Not available"
            customer_name = loan.customer.name
        else:
            availability = "Available"
            customer_name = "N/A"

        book_info = {
            "id": book.id,
            "name": book.name,
            "author": book.author,
            "year_published": book.year_published,
            "type": book.type,
            "availability": availability,
            "customer_name": customer_name
        }

        book_details.append(book_info)

    if current_user == 'admin':
        return jsonify({"books": book_details}), 200
    else:
        return jsonify({"books": [book for book in book_details if book["availability"] == "Available"]}), 200


@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"msg": "Username already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "Registration successful"}), 200

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = User.query.filter_by(username=username).first()
    if user:
        if bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"msg": "Invalid password"}), 401
    else:
        return jsonify({"msg": "User not found"}), 401

@app.route('/add_admin', methods=['POST'])
def add_admin():
    # Get the admin's username and password from the request
    admin_username = 'oferk'
    admin_password = '1505'  # You should hash this password for security in a real application

    # Check if the admin user already exists in the database
    existing_admin = User.query.filter_by(username=admin_username).first()
    if existing_admin:
        return jsonify({"message": "Admin user already exists"}), 400

    # Hash the admin's password before storing it in the database
    hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

    # Create and add the admin user to the database
    new_admin = User(username=admin_username, password=hashed_password)
    db.session.add(new_admin)
    db.session.commit()

    return jsonify({"message": "Admin user added successfully"}), 200

@app.route('/admin/dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    current_user = get_jwt_identity()
    
    # Check if the current user is the admin (oferk)
    if current_user == 'oferk':
        # Query the database to get the book list and customer rentals
        books = Book.query.all()
        customers = Customer.query.all()
        
        # Construct a response with book list and customer rentals data
        book_data = [{"id": book.id, "name": book.name, "author": book.author, "year_published": book.year_published, "type": book.type} for book in books]
        customer_data = [{"id": customer.id, "name": customer.name, "city": customer.city, "age": customer.age, "gender": customer.gender} for customer in customers]

        return jsonify({"books": book_data, "customers": customer_data})
    else:
        return jsonify({"message": "Access denied. Only admin can view this page."}), 403
        


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'msg': f'Welcome {current_user}, you are viewing a protected endpoint!'})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_initial_books()
        add_test_data()
    app.run(debug=True)
# 999