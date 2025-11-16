import bcrypt
from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = "2mOF=?*@89U.)!<rBQ`Zcl}a42yhn8zg~OQ6y!V#@\vkSfbN^D"  # change this to something long/random
COOKIE_NAME = "admin_session"

# ⚠️ CHANGE THIS to your real admin password:
PLAINTEXT_ADMIN_PASSWORD = ".\_4*2'2J}nc&A@.c$9wBv]erl92>OT':d42&$:`nB45Mm1kc+"

# Hash password once
ADMIN_PASSWORD_HASH = bcrypt.hashpw(
    PLAINTEXT_ADMIN_PASSWORD.encode(),
    bcrypt.gensalt()
)

# Cookie signer
serializer = URLSafeTimedSerializer(SECRET_KEY)


def verify_password(password: str) -> bool:
    return bcrypt.checkpw(password.encode(), ADMIN_PASSWORD_HASH)


def create_session():
    return serializer.dumps({"user": "admin"})


def verify_session(cookie_value: str) -> bool:
    try:
        data = serializer.loads(cookie_value, max_age=86400)  # 24 hours
        return data.get("user") == "admin"
    except:
        return False