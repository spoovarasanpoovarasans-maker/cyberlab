from app.security import (
    RateLimiter,
    csrf_ok,
    hash_password,
    sha256_hex,
    verify_password,
)


def test_password_roundtrip():
    hashed = hash_password("correct horse battery staple")
    assert verify_password(hashed, "correct horse battery staple")
    assert not verify_password(hashed, "wrong password")


def test_sha256_is_stable():
    assert sha256_hex("FLAG{x}") == sha256_hex("FLAG{x}")
    assert sha256_hex("FLAG{x}") != sha256_hex("FLAG{y}")


def test_csrf_comparison():
    assert csrf_ok("token", "token")
    assert not csrf_ok("token", "other")
    assert not csrf_ok(None, "token")
    assert not csrf_ok("token", None)


def test_rate_limiter_sliding_window():
    limiter = RateLimiter()
    assert limiter.allow("login:1.2.3.4", 3, 60)
    assert limiter.allow("login:1.2.3.4", 3, 60)
    assert limiter.allow("login:1.2.3.4", 3, 60)
    assert not limiter.allow("login:1.2.3.4", 3, 60)
    assert limiter.allow("login:5.6.7.8", 3, 60)
