from passlib.context import CryptContext
from hashlib import sha256

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_ctx.verify(plain_password, hashed_password)



def hash_token(token: str) -> str:
    # store hashed refresh token server-side (SHA256) to avoid storing the raw token
    return sha256(token.encode("utf-8")).hexdigest()
