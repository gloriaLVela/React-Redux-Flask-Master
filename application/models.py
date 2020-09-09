from  .encrypt_decrypt import decrypt_password, encrypt_password
from index import db


class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

    def __init__(self, email, password):
        encrypted_password = encrypt_password(password)
        self.email = email
        self.active = True
        self.password = encrypted_password


    @staticmethod
    def get_user_with_email_and_password(email, password):
        user = User.query.filter_by(email=email).first()
        
        if user:
            print("old password", decrypt_password(user.password), flush=True)
            return user
        else:
            return None
