from fastapi import Header, HTTPException, status

from config import settings


def require_service_auth(x_api_key: str | None = Header(default=None)) -> None:
    if not settings.API_AUTH_ENABLED:
        return
    if not x_api_key or x_api_key != settings.API_KEY_SERVICE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service API key",
        )


def require_analyst_auth(x_analyst_key: str | None = Header(default=None)) -> None:
    if not settings.API_AUTH_ENABLED:
        return
    if not x_analyst_key or x_analyst_key != settings.API_KEY_ANALYST:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing analyst API key",
        )
