from flask import Flask, request
from config import Config
from app.extensions import db
from flask_login import LoginManager
import socket
from flask_talisman import Talisman

login_manager = LoginManager()
server_ip = socket.gethostbyname(socket.gethostname())

def create_app(config_class=Config):
    app = Flask(__name__,static_folder='static')

    @app.after_request
    def remove_server_header(response):
        response.headers.pop('Server', None)
        return response

    csp = {'default-src': '\'self\'',}
    Talisman(app, content_security_policy=csp)

    app.config.from_object(config_class)

    with app.app_context():
        db.init_app(app)

        from app.models import User, Note, UserIP

        db.create_all()

        if not User.query.filter_by(username='admin').first():
            user = User(username='admin', email='admin@example.com')
            user.init_password('passwd')
            db.session.add(user)
            user = User(username='mikib', email='mikib@example.com')
            user.init_password('passwd')
            db.session.add(user)
            user_ip = UserIP(ip_address=server_ip, user_id=1, is_associated=True)
            db.session.add(user_ip)
            user_ip = UserIP(ip_address=server_ip, user_id=2, is_associated=True)
            db.session.add(user_ip)
            note = Note(content='Public default note!', encrypted=False, public=True, user_id=1)
            db.session.add(note)
            note = Note(content='Private default note!', encrypted=False, public=False, user_id=2)
            db.session.add(note)
            db.session.commit()

    login_manager.init_app(app)

    from app.routes import bp
    app.register_blueprint(bp)

    return app
