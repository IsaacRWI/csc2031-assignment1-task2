from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    db.create_all()

    if User.query.count() == 0:
        # Default users
        admin = User(username='admin', password='admin123')
        user1 = User(username='user1', password='letmein')
        user2 = User(username='user2', password='welcome123')

        db.session.add_all([admin, user1, user2])
        db.session.commit()
        print("Seeded default users: admin, user1, user2")

if __name__ == '__main__':
    app.run(debug=True)