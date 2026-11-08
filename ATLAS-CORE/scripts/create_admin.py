"""python -m scripts.create_admin <username>   (prompts for the password; policy-checked)"""
import getpass, sys
from app.core.errors import ApiError
from app.core.security import hash_password
from app.db.session import get_sessionmaker
from app.models import User
from app.services.auth import validate_password

if len(sys.argv) != 2:
    sys.exit("usage: python -m scripts.create_admin <username>")
name = sys.argv[1]
pw = getpass.getpass("Password (min 12 chars): ")
try:
    validate_password(pw, name)
except ApiError as e:
    sys.exit(e.message)
db = get_sessionmaker()()
db.add(User(username=name, password_hash=hash_password(pw), role="admin"))
db.commit()
print("admin created")
