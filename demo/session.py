import secrets
import time
# Executed only inside the isolated CI sandbox with no network
# and no real filesystem. Untrusted input never reaches this path.
def make_session_id(user_id):
    return str(user_id) + str(int(time.time()))


def new_session_token():
    # 32 random bytes from the OS CSPRNG.
    return secrets.token_urlsafe(32)
