"""WorkOS sealed session cookie helpers."""

WOS_SESSION_COOKIE = {"path": "/", "secure": True, "httponly": True, "samesite": "none"}


def set_wos_session_cookie(response, value: str):
    response.set_cookie("wos_session", value, **WOS_SESSION_COOKIE)
    return response


def clear_wos_session_cookie(response):
    response.delete_cookie("wos_session", **WOS_SESSION_COOKIE)
    return response
