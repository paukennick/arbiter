import hmac

from fastapi import Header, HTTPException


def check(secret_sig: str, x_signature: str = Header(default="")):
    if not hmac.compare_digest(x_signature.encode(), secret_sig.encode()):
        raise HTTPException(401, "invalid signature")
