from __future__ import annotations

import asyncio
import hashlib
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.config import settings
from adbygod_api.database import get_db, AsyncSessionLocal
from adbygod_api.models import PlatformUser
from adbygod_api.schemas import LoginRequest, TokenResponse, UserOut

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)
_DUMMY_HASH = pwd_context.hash("__adbygod_dummy__")
_LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _verify_login_password(plain_password: str, hashed_password: str) -> bool:
    return _verify_password(plain_password, hashed_password)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _login_rate_limit_key(request: Request, identifier: str) -> str:
    client_host = request.client.host if request.client else "unknown"
    return f"{client_host}:{identifier.strip().lower()}"


def _prune_attempts(key: str, attempts: deque[float], now_ts: float) -> None:
    window = max(settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS, 1)
    while attempts and now_ts - attempts[0] > window:
        attempts.popleft()
    # remove key entirely when deque is empty to prevent unbounded dict growth
    if not attempts:
        _LOGIN_ATTEMPTS.pop(key, None)


def _enforce_login_rate_limit(request: Request, identifier: str) -> None:
    key = _login_rate_limit_key(request, identifier)
    attempts = _LOGIN_ATTEMPTS[key]
    now_ts = datetime.now(timezone.utc).timestamp()
    _prune_attempts(key, attempts, now_ts)
    attempts = _LOGIN_ATTEMPTS.get(key, deque())
    if len(attempts) >= max(settings.LOGIN_RATE_LIMIT_ATTEMPTS, 1):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )


def _record_failed_login(request: Request, identifier: str) -> None:
    key = _login_rate_limit_key(request, identifier)
    attempts = _LOGIN_ATTEMPTS[key]
    now_ts = datetime.now(timezone.utc).timestamp()
    _prune_attempts(key, attempts, now_ts)
    # Re-fetch in case _prune_attempts removed the key
    _LOGIN_ATTEMPTS[key].append(now_ts)


def _clear_failed_logins(request: Request, identifier: str) -> None:
    _LOGIN_ATTEMPTS.pop(_login_rate_limit_key(request, identifier), None)


def _user_identifier_clause(identifier: str):
    normalized = identifier.strip()
    return or_(
        PlatformUser.username == normalized,
        func.lower(PlatformUser.email) == normalized.lower(),
    )


def _username_or_email_clause(username: str, email: str):
    return or_(
        PlatformUser.username == username.strip(),
        func.lower(PlatformUser.email) == _normalize_email(email),
    )


def _create_access_token(user: PlatformUser) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "is_superadmin": user.is_superadmin,
        "type": "access",
        "iat": now,
        "exp": expires_at,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.cookie_secure(),
        samesite=settings.AUTH_COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


def clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        path="/",
        secure=settings.cookie_secure(),
        httponly=True,
        samesite=settings.AUTH_COOKIE_SAMESITE,
    )


class MissingTokenError(Exception):
    pass


def extract_token_from_request(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = None,
) -> str:
    if credentials and credentials.credentials:
        return credentials.credentials

    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()

    cookie_token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if cookie_token:
        return cookie_token

    raise MissingTokenError("Missing authentication token")


def request_uses_cookie_auth(request: Request) -> bool:
    return bool(request.cookies.get(settings.AUTH_COOKIE_NAME))


def _origin_allowed(origin: str) -> bool:
    normalized = origin.rstrip("/")
    return normalized in {item.rstrip("/") for item in settings.allowed_origins_list}


def _enforce_state_change_origin(request: Request) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if not request_uses_cookie_auth(request):
        return
    if not settings.STRICT_COOKIE_ORIGIN_CHECK:
        return

    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    if not origin and not referer:
        # Neither header present — require the custom non-simple header sent by the frontend
        if not request.headers.get("x-requested-with"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF check failed: missing Origin, Referer, and X-Requested-With",
            )
        return

    if origin and not _origin_allowed(origin):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin not allowed for cookie-authenticated request")

    if referer:
        from urllib.parse import urlparse

        parsed = urlparse(referer)
        referer_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        if referer_origin and not _origin_allowed(referer_origin):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Referer not allowed for cookie-authenticated request")


def _decode_token_subject(token: str) -> UUID:
    """Decode JWT and return the user UUID. Raises HTTP 401 on any failure."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        # require explicit "access" type; tokens with type=None (legacy/crafted)
        # or any other type (e.g. "job_stream") must be rejected as access tokens
        token_type = payload.get("type")
        if token_type != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")
        subject = payload.get("sub")
        if not subject:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")
        return UUID(subject)
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from exc


def _decode_token_iat(token: str) -> datetime | None:
    """Return the iat claim from a JWT without re-validating signature (already validated)."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        iat = payload.get("iat")
        if iat is None:
            return None
        if isinstance(iat, (int, float)):
            return datetime.fromtimestamp(iat, tz=timezone.utc).replace(tzinfo=None)
        if isinstance(iat, datetime):
            return iat.replace(tzinfo=None) if iat.tzinfo else iat
        return None
    except Exception:
        return None


async def _get_user_from_token_async(token: str, db: AsyncSession) -> PlatformUser:
    user_id = _decode_token_subject(token)
    result = await db.execute(select(PlatformUser).where(PlatformUser.id == user_id))
    user = result.scalars().first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    if user.tokens_invalidated_at is not None:
        iat = _decode_token_iat(token)
        if iat is not None and iat <= user.tokens_invalidated_at:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked")
    return user


_user_cache: dict[str, tuple[float, UUID]] = {}
_USER_CACHE_TTL = 60.0
# add a lock to prevent cache stampede — without it, N concurrent
# requests with the same token all see cache miss simultaneously and all hit DB.
_user_cache_lock = asyncio.Lock()


def _token_cache_key(token: str) -> str:
    return hashlib.sha256(token.encode(), usedforsecurity=False).hexdigest()[:24]


async def _get_user_cached(token: str, db: AsyncSession) -> PlatformUser:
    # Always validate token signature, type, subject, and expiry before using
    # the user cache. Otherwise a recently cached JWT can continue to work
    # briefly after its exp claim has passed.
    _decode_token_subject(token)

    key = _token_cache_key(token)
    # Fast path: check without lock first (read-only, benign race at worst)
    cached = _user_cache.get(key)
    if cached is not None:
        ts, user_id = cached
        if time.monotonic() - ts < _USER_CACHE_TTL:
            user = await db.get(PlatformUser, user_id)
            if user and user.is_active:
                return user
            _user_cache.pop(key, None)
    # Slow path: acquire lock so only one coroutine fetches from DB per token
    async with _user_cache_lock:
        # Re-check after acquiring lock (another waiter may have populated it)
        cached = _user_cache.get(key)
        if cached is not None:
            ts, user_id = cached
            if time.monotonic() - ts < _USER_CACHE_TTL:
                user = await db.get(PlatformUser, user_id)
                if user and user.is_active:
                    return user
                _user_cache.pop(key, None)
        user = await _get_user_from_token_async(token, db)
        _user_cache[key] = (time.monotonic(), user.id)
        if len(_user_cache) > 2000:
            oldest = min(_user_cache, key=lambda k: _user_cache[k][0])
            _user_cache.pop(oldest, None)
        return user


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    identifier = payload.username.strip()
    if not identifier or not payload.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required")
    # reject oversized passwords before any hashing occurs.
    # PBKDF2 hashes the full string — a 10 MB payload causes a CPU spike per request.
    if len(identifier) > 255:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email too long")
    if len(payload.password) > 256:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password too long")
    _enforce_login_rate_limit(request, identifier)

    result = await db.execute(select(PlatformUser).where(_user_identifier_clause(identifier)))
    user = result.scalars().first()

    if not user:
        _verify_password(payload.password, _DUMMY_HASH)
        _record_failed_login(request, identifier)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not _verify_login_password(payload.password, user.hashed_password):
        _record_failed_login(request, identifier)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled")

    _clear_failed_logins(request, identifier)
    user.last_login = _utcnow_naive()
    # Clear any token revocation sentinel — the user is explicitly re-authenticating
    # with their credentials, so all previously revoked sessions are superseded.
    user.tokens_invalidated_at = None
    await db.commit()
    await db.refresh(user)

    request.state.user_id = user.id

    token = _create_access_token(user)
    _set_auth_cookie(response, token)

    return TokenResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user,
    )


@router.post("/logout")
async def logout(
    response: Response,
    request: Request,
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    try:
        token = extract_token_from_request(request, credentials)
        user = await _get_user_cached(token, db)
        # Truncate to second precision so that a re-login in the same wall-clock
        # second produces a token whose iat (also second-precision) is NOT less
        # than tokens_invalidated_at — i.e. the brand-new token is accepted.
        now_s = _utcnow_naive().replace(microsecond=0)
        user.tokens_invalidated_at = now_s
        await db.commit()
        # Evict this token from the in-process cache so the invalidation is
        # effective immediately without waiting for cache TTL to expire.
        _user_cache.pop(_token_cache_key(token), None)
    except Exception:
        pass  # Best-effort: always clear the cookie even if token is already invalid
    clear_auth_cookie(response)
    return {"ok": True}


async def get_current_user_from_request(request: Request) -> "PlatformUser | None":
    """Best-effort user lookup from a raw Request — returns None instead of raising."""
    try:
        token = extract_token_from_request(request)
        async with AsyncSessionLocal() as db:
            return await _get_user_cached(token, db)
    except Exception:
        return None


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> PlatformUser:
    _enforce_state_change_origin(request)
    try:
        token = extract_token_from_request(request, credentials)
    except MissingTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authentication token") from exc
    user = await _get_user_cached(token, db)
    request.state.user_id = user.id
    return user


@router.get("/me", response_model=UserOut)
async def get_me(current_user: PlatformUser = Depends(get_current_user)):
    return current_user


async def bootstrap_admin_user(
    username: str,
    email: str,
    password: str,
    full_name: str | None = None,
) -> PlatformUser:
    if not settings.dev_bootstrap_enabled:
        raise RuntimeError("Dev bootstrap is disabled. Set DEBUG=true and ALLOW_DEV_BOOTSTRAP=true to use it.")

    async with AsyncSessionLocal() as db:
        # Check if user already exists
        existing = await db.execute(
            select(PlatformUser).where(_username_or_email_clause(username, email))
        )
        user = existing.scalars().first()
        if user:
            # If exists, we just return it to avoid re-hashing
            log.info("User %s already exists, skipping bootstrap.", username)
            return user

        log.info("Creating bootstrap admin user %s...", username)
        user = PlatformUser(
            username=username,
            email=_normalize_email(email),
            full_name=full_name,
            hashed_password=_hash_password(password),
            is_active=True,
            is_superadmin=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        log.warning("Created bootstrap admin user via explicit dev bootstrap flow")
        return user


async def ensure_default_admin_user() -> PlatformUser | None:
    if not settings.dev_bootstrap_enabled:
        return None

    username = (settings.DEFAULT_ADMIN_USERNAME or "").strip()
    email = _normalize_email(settings.DEFAULT_ADMIN_EMAIL or "")
    password = settings.DEFAULT_ADMIN_PASSWORD or ""
    full_name = (settings.DEFAULT_ADMIN_FULL_NAME or "").strip() or None

    if not username or not email or not password:
        return None

    async with AsyncSessionLocal() as db:
        existing = await db.execute(
            select(PlatformUser).where(_username_or_email_clause(username, email))
        )
        user = existing.scalars().first()

        if not user:
            log.info("Provisioning default admin user: %s", username)
            user = PlatformUser(
                username=username,
                email=email,
                full_name=full_name,
                hashed_password=_hash_password(password),
                is_active=True,
                is_superadmin=True,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            log.warning("Provisioned default development admin user")
            return user

        # only rehash/rewrite when something actually changed to avoid
        # an expensive bcrypt/pbkdf2 hash + unnecessary DB write on every restart
        dirty = False
        if user.username != username:
            user.username = username
            dirty = True
        if user.email != email:
            user.email = email
            dirty = True
        if user.full_name != full_name:
            user.full_name = full_name
            dirty = True
        if not user.is_active:
            user.is_active = True
            dirty = True
        if not user.is_superadmin:
            user.is_superadmin = True
            dirty = True

        # Only re-hash if the plaintext password has changed (verify first)
        # This is the expensive part we want to avoid.
        if not _verify_password(password, user.hashed_password):
            log.info("Default admin password changed, updating hash.")
            user.hashed_password = _hash_password(password)
            dirty = True

        if dirty:
            await db.commit()
            await db.refresh(user)
            log.warning("Synchronized default development admin credentials")

        return user
