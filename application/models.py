from index import db
from .encryptII import encrypt, decrypt


class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

    def __init__(self, email, password):
        self.email = email
        self.active = True
        encrypted_password = encrypt("THis Key!",password)
        self.password = password

    # @staticmethod
    # def hashed_password(password):
    #     return bcrypt.generate_password_hash(password).decode("utf-8")

    @staticmethod
    def get_user_with_email_and_password(email, password):
        user = User.query.filter_by(email=email).first()
        if user:
            print("password", decrypt_password(user.password))
            return user
        else:
            return None
