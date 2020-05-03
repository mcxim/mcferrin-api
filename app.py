from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
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
    username = db.Column(db.String(100), unique=True)
    data = db.Column(db.String())

    def __init__(self, username, data=""):
        self.username = username
        self.data = data


class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User

    id = ma.auto_field()
    username = ma.auto_field()
    data = ma.auto_field()


user_schema = UserSchema()
users_schema = UserSchema(many=True)


@app.route("/user", methods=["POST"])
def create_user():
    print("request.json: " + str(request.json))
    if not request.json:
        return jsonify({"Error": "request json is present."}), 403
    missing_fields = [
        field for field in ["data", "username"] if field not in request.json
    ]
    if missing_fields:
        return jsonify(
            {"Error": "The following fields are missing: " + str(missing_fields)}
        )
    username = request.json["username"]
    data = request.json["data"]
    if User.query.filter_by(username=username).first() != None:
        return (
            jsonify({"Error": "This username already exists in the database."}),
            403,
        )
    new_user = User(username, data)
    db.session.add(new_user)
    db.session.commit()
    return user_schema.jsonify(new_user), 201


@app.route("/user", methods=["GET"])
def get_all_users():
    return jsonify(users_schema.dump(User.query.all())), 200


@app.route("/user/<id>", methods=["GET"])
def get_user(id):
    return user_schema.jsonify(User.query.get(id)), 200


@app.route("/user/<id>", methods=["PUT"])
def update_user(id):
    user = User.query.get(id)
    for field in request.json:
        if request.json[field] != " ":
            setattr(user, field, request.json[field])
    db.session.commit()
    return user_schema.jsonify(user)


@app.route("/user/<id>", methods=["DELETE"])
def delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return user_schema.jsonify(user)


if __name__ == "__main__":
    app.run(debug=True)
