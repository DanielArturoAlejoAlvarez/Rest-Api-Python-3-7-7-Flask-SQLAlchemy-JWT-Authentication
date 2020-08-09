from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os

import uuid
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta

import jwt

from functools import wraps

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Config Database
app.config['SECRET_KEY'] = 'dhdQq.S17Ex_YlWwwz9ncgglIQBfiAekHgZW6Rxb7H_4R7OmUxzV14fkvGo1ss0Z'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'sqlite.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)


# Class User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(512))
    admin = db.Column(db.Boolean)

    def __init__(self, public_id, name, email, username, password, avatar, admin):
        self.public_id = public_id
        self.name = name
        self.email = email
        self.username = username
        self.password = password
        self.avatar = avatar
        self.admin = admin

    def __repr__(self):
        return '<User> %r' % self.name

# Class Product


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey(
        'category.id'), nullable=False)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(512), nullable=False)
    date_reg = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    category = db.relationship(
        'Category', backref=db.backref('products', lazy=True))

    def __init__(self, category_id, name, description, price, stock, image_url):
        self.category_id = category_id
        self.name = name
        self.description = description
        self.price = price
        self.stock = stock
        self.image_url = image_url

    def __repr__(self):
        return '<Post %r>' % self.name


# Class Category
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    date_reg = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Category %r>' % self.name

# Create Schemas


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'public_id', 'name', 'email',
                  'username', 'password', 'avatar', 'admin')


class ProductSchema(ma.Schema):
    class Meta:
        fields = ('id', 'category_id', 'name', 'description',
                  'price', 'stock', 'image_url')


class CategorySchema(ma.Schema):
    class Meta:
        fields = ('id', 'name')


# Init Schemas
user_schema = UserSchema()
users_schema = UserSchema(many=True)
product_schema = ProductSchema()
products_schema = ProductSchema(many=True)
category_schema = CategorySchema()
categories_schema = CategorySchema(many=True)

# Routes

# Authentication
# Login User


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Coult not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('Coult not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])
        return jsonify({
            'token': token.decode('UTF-8')
        })
    return make_response('Coult not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


# Token Authenticated
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'msg': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()

        except:
            return jsonify({'msg': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# REST API
# Create User
@app.route('/user', methods=['POST'])
@token_required
def add_user(current_user):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    public_id = str(uuid.uuid4())
    name = data['name']
    email = data['email']
    username = data['username']
    password = hashed_password
    avatar = data['avatar']
    admin = False

    new_user = User(public_id, name, email, username, password, avatar, admin)

    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)

# List User


@app.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)

# Single User


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"msg": "User no found!"})
    return user_schema.jsonify(user)

# Update User


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def update_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"msg": "User no found!"})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    user.public_id = str(uuid.uuid4())
    user.name = data['name']
    user.email = data['email']
    user.username = data['username']
    user.password = hashed_password
    user.avatar = data['avatar']
    user.admin = False

    db.session.commit()

    return user_schema.jsonify(user)


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"msg": "User no found!"})
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)


# Create Category
@app.route('/category', methods=['POST'])
@token_required
def add_category(current_user):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    name = request.json['name']

    new_category = Category(name)

    db.session.add(new_category)
    db.session.commit()

    return category_schema.jsonify(new_category)

# List Category


@app.route('/categories', methods=['GET'])
@token_required
def get_categories(current_user):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    all_categories = Category.query.all()
    result = categories_schema.dump(all_categories)
    return jsonify(result)

# Single Category


@app.route('/category/<id>', methods=['GET'])
@token_required
def get_category(current_user, id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    category = Category.query.get(id)
    return category_schema.jsonify(category)

# Update Category


@app.route('/category/<id>', methods=['PUT'])
@token_required
def update_category(current_user, id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    category = Category.query.get(id)

    name = request.json['name']

    category.name = name

    db.session.commit()

    return category_schema.jsonify(category)

# Delete Category


@app.route('/category/<id>', methods=['DELETE'])
@token_required
def delete_category(current_user, id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    category = Category.query.get(id)
    db.session.delete(category)
    db.session.commit()
    return category_schema.jsonify(category)

# Create Product


@app.route('/product', methods=['POST'])
@token_required
def add_product(current_user):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    category_id = request.json['category_id']
    name = request.json['name']
    description = request.json['description']
    price = request.json['price']
    stock = request.json['stock']
    image_url = request.json['image_url']

    new_product = Product(category_id, name, description,
                          price, stock, image_url)

    db.session.add(new_product)
    db.session.commit()

    return product_schema.jsonify(new_product)

# List Products


@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    all_products = Product.query.all()
    result = products_schema.dump(all_products)
    return jsonify(result)

# Single Product


@app.route('/product/<id>', methods=['GET'])
@token_required
def get_product(current_user, id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    product = Product.query.get(id)
    return product_schema.jsonify(product)

# Update Product


@app.route('/product/<id>', methods=['PUT'])
@token_required
def update_product(current_user, id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    product = Product.query.get(id)

    category_id = request.json['category_id']
    name = request.json['name']
    description = request.json['description']
    price = request.json['price']
    stock = request.json['stock']
    image_url = request.json['image_url']

    product.category_id = category_id
    product.name = name
    product.description = description
    product.price = price
    product.stock = stock
    product.image_url = image_url

    db.session.commit()

    return product_schema.jsonify(product)

# Delete Product


@app.route('/product/<id>', methods=['DELETE'])
@token_required
def delete_product(current_user, id):
    if not current_user.admin:
        return jsonify({'msg': 'Cannot perform that function!'})
    product = Product.query.get(id)
    db.session.delete(product)
    db.session.commit()
    return product_schema.jsonify(product)


@app.route('/', methods=["GET"])
def get():
   return jsonify({
     "ok": True,
     "msg": "REST API with FLASK"
   })

# Run server
if __name__ == "__main__":
    app.run(debug=True)

