import os
from app import create_app, db
from app.models import User

db_path = 'instance/users.db'

if os.path.exists(db_path):
    os.remove(db_path)
    print("Existing database deleted.")

app = create_app()

with app.app_context():
    db.create_all()

    if User.query.count() == 0:
        # Default users
        # admin = User(username='admin', password='admin123')
        # user1 = User(username='user1', password='letmein')
        # user2 = User(username='user2', password='welcome123')
        admin = User(username = "admin")
        admin.hash_password("admin123")  # uses hashed passwords through bcrypt instead of plain text
        user1 = User(username = "user1")
        user1.hash_password('letmein')
        user2 = User(username = "user2")
        user2.hash_password('welcome123')

        db.session.add_all([admin, user1, user2])
        db.session.commit()
        print("Seeded default users: admin, user1, user2")