"""
Authentication
==============
JWT token creation, verification, and the /auth/login endpoint.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, status
from jose import JWTError, jwt
from pydantic import BaseModel

from app.config import settings
from app.database import fetch_user_by_username, get_db, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def create_access_token(user_id: int, username: str) -> str:
    """
    Sign a JWT containing the user's id and username.

    The 'sub' (subject) claim carries the user ID as a string — this is
    what the middleware reads to look up the user on each request.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub":      str(user_id),
        "username": username,
        "exp":      expire,
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Verify a JWT and return the decoded payload.

    Raises HTTP 401 on any failure (expired, tampered, missing sub).
    Called by the middleware on every /api/* request.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise ValueError("Missing sub claim")
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Login endpoint
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    user_id: int


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    """
    Exchange username + password for a signed JWT.

    Returns the token plus the username and user_id so the frontend can
    display the logged-in user without making a separate /me call.
    """
    with get_db() as conn:
        user = fetch_user_by_username(conn, body.username)

    if user is None or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
        )

    token = create_access_token(user["id"], user["username"])
    return TokenResponse(
        access_token=token,
        username=user["username"],
        user_id=user["id"],
    )
