# Rest-Api-Python-3-7-7-Flask-SQLAlchemy-JWT-Authentication

## Description

This repository is a Software of Application with Python, Flask, SQLAlchemy (ORM), Marshmallow, JWT Authentication and SQLite.

## Installation

Using Flask, SQLAlchemy, Marshmallow, SQLite3,etc preferably.

## DataBase

Using SQLite3 preferably.

## Apps

Using Postman, Insomnia, etc.

## Usage

```html
$ git clone https://github.com/DanielArturoAlejoAlvarez/Rest-Api-Python-3-7-7-Flask-SQLAlchemy-JWT-Authentication.git
[NAME APP]

$ pipenv shell

CREATE DATABASE AND MIGRATIONS

$ python

$ from app import db

$ db.create_all()

RUN SERVER

$ python app.py
```

Follow the following steps and you're good to go! Important:

![alt text]()

## Coding

### Config

```python
...
app.config['SECRET_KEY'] = 'dhdQq.S17Ex_YlWwwz9ncgglIQBfiAekHgZW6Rxb7H_4R7OmUxzV14fkvGo1ss0Z'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'sqlite.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)
...
```

### Models

```python
...
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


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'public_id', 'name', 'email',
                  'username', 'password', 'avatar', 'admin')

user_schema = UserSchema()
users_schema = UserSchema(many=True)
...
```

### Comtrollers

```python
...
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
...
```

### Authentication

```python
...
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
...
```

### Middlewares

```python
...
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
...

```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/DanielArturoAlejoAlvarez/Rest-Api-Python-3-7-7-Flask-SQLAlchemy-JWT-Authentication. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
````
