# EXPECT: gen_missing_security_logging
from werkzeug.security import check_password_hash


def login(user, password):
    if check_password_hash(user.pw_hash, password):
        return issue_token(user)
    return None
