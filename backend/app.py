from flask import Flask, request, abort, jsonify, session
from flask_bcrypt import Bcrypt
from flask_session import Session
from models import db, User, Character
from config import ApplicationConfig

app = Flask(__name__)
app.config.from_object(ApplicationConfig)

bcrypt = Bcrypt(app)
server_session = Session(app)
db.init_app(app)


with app.app_context():
    db.create_all()


@app.route("/@me")
def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Unauthorized"})
    
    user = User.query.filter_by(id=user_id).first()
    return jsonify({
        "id": user.id,
        "email": user.email
    })





@app.route("/register", methods=['POST'])
def register_user():
    email = request.json["email"]
    password = request.json["password"]

    user_exists = User.query.filter_by(email=email).first() is not None

    if user_exists:
        return jsonify({"error": "User already exists"}), 409
    
    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "id": new_user.id,
        "email": new_user.email
    })

@app.route("/login", methods=["POST"])
def login_user():
    email = request.json["email"]
    password = request.json["password"]

    user = User.query.filter_by(email=email).first()

    if User is None:
        return jsonify({"error": "Unauthorized"}), 401
    
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Unauthorized"}), 401
    
    session["user_id"] = user.id

    return jsonify({
        "id": user.id,
        "email": user.email
    })

@app.route("/name", methods=["POST"])
def add_name():
    user_id = session.get("user_id")
    name = request.json["name"]
    
    if not user_id:
        return jsonify({"error": "Unauthorized"})
    new_character = Character(id=user_id, name=name)
    db.session.add(new_character)
    db.session.commit()

    return jsonify({
        "id": new_character.id,
        "name": new_character.name
    })

@app.route("/createchar", methods=["POST"])
def add_char():
    user_id = session.get("user_id")
    name = request.json["name"]
    cclass = request.json["class"]
    level = request.json["level"]
    race = request.json["race"]
    
    if not user_id:
        return jsonify({"error": "Unauthorized"})
    new_character = Character(id=user_id, name=name, cclass=cclass, level=level, race=race)
    db.session.add(new_character)
    db.session.commit()

    return jsonify({
        "id": new_character.id,
        "name": new_character.name
    })

@app.route("/getname")
def get_name():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Unauthorized"})
    
    user = Character.query.filter_by(id=user_id).first()
    
    return jsonify({
        "name": user.name,
        "class": user.cclass,
        "race": user.race,
        "level": user.level
    })

if __name__ == "__main__":
    app.run(debug=True)