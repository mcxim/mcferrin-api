from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
import base64
import binascii
import os

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config[
    "SECRET_KEY"
] = "\xa6\xc6\xc4\xa8\xcb\x19Z\x9f\xd4\xf3\xe7\xf1\xa6b\xe8\xf5`+\xa2\xf0\x8aO\xe3\xa6"
# Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
    basedir, "db.sqlite"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Init db
db = SQLAlchemy(app)
# Init ma
ma = Marshmallow(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    data = db.Column(db.String())

    def __init__(self, public_id, username, password, data=""):
        self.public_id = public_id
        self.username = username
        self.password = password
        self.data = data


class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    id = ma.auto_field()
    public_id = ma.auto_field()
    username = ma.auto_field()
    password = ma.auto_field()
    data = ma.auto_field()


class PublicUserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    public_id = ma.auto_field()
    username = ma.auto_field()


user_schema = UserSchema()
users_schema = PublicUserSchema(many=True)
all_info_schema = UserSchema(many=True)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "x-access-tokens" in request.headers:
            token = request.headers["x-access-tokens"]
        if not token:
            return jsonify({"Error": "a valid tolkien is missing"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
            current_user = User.query.filter_by(public_id=data["public_id"]).first()
        except Exception as e:
            return jsonify({"Error": "tolkien is invalid " + str(e)}), 401
        return f(current_user, *args, **kwargs)

    return decorator


@app.route("/register", methods=["POST"])
def create_user():
    if not request.json:
        return jsonify({"Error": "request json is not present."}), 400
    missing_fields = [
        field for field in ["username", "password", "data"] if field not in request.json
    ]
    if missing_fields:
        return jsonify(
            {"Error": "The following fields are missing: " + str(missing_fields)}
        )
    username = request.json["username"]
    b64_login = request.json["password"]
    data = request.json["data"]
    if User.query.filter_by(username=username).first() != None:
        return jsonify({"Error": "This username already exists in the database."}), 400
    try:
        login_hash = base64.b64decode(b64_login)
    except binascii.Error:
        return jsonify({"Error": "Invalid base64 login hash"}), 400
    stored_hash = generate_password_hash(login_hash, method="pbkdf2:sha256:100100")
    new_user = User(
        public_id=str(uuid.uuid4()), username=username, password=stored_hash, data=data
    )
    db.session.add(new_user)
    db.session.commit()
    return (user_schema.jsonify(new_user), 201)


@app.route("/login", methods=["GET"])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({"Error": "Could not verify - Login required"}), 401
    try:
        login_hash = base64.b64decode(auth.password)
    except binascii.Error:
        return jsonify({"Error": "Invalid base64 login hash"}), 401
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return jsonify(
            {"Error": "Username invalid. please check your spelling to register."}
        ), 401
    if check_password_hash(user.password, login_hash):
        token = jwt.encode(
            {
                "public_id": user.public_id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
        )
        return jsonify({"token": token.decode("UTF-8")})
    return jsonify({"Error": "Invalid password."}), 401


@app.route("/user", methods=["GET"])
@token_required
def get_user(user):
    return user_schema.jsonify(user), 200


@app.route("/user/data", methods=["GET"])
@token_required
def get_user_data(user):
    return jsonify({"data": user.data})


@app.route("/user/data", methods=["PUT"])
@token_required
def update_data(user):
    user.data = request.json["data"]
    db.session.commit()
    return ("", 204)


@app.route("/user", methods=["DELETE"])
@token_required
def delete_user(user):
    db.session.delete(user)
    db.session.commit()
    return ("", 204)


@app.route("/admin/<id>", methods=["DELETE"])
def admin_delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)


@app.route("/admin", methods=["GET"])
def all_info():
    return all_info_schema.jsonify(User.query.all())


@app.route("/admin/<id>", methods=["PUT"])
def admin_put(id):
    for field in request.json:
        setattr(user, field, request.json[field])
    db.session.commit()
    return user_schema.jsonify(user), 202


@app.route("/protected", methods=["GET"])
@token_required
def sample_protected(user):
    return "how did you get here, " + str(user.__dict__["username"]) + "?"


if __name__ == "__main__":
    app.run(debug=True)
