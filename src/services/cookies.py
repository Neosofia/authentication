"""Identity-provider session cookie helpers."""

IDP_SESSION_COOKIE_NAME = "wos_session"
IDP_SESSION_COOKIE = {"path": "/", "secure": True, "httponly": True, "samesite": "none"}


def set_idp_session_cookie(response, value: str):
    response.set_cookie(IDP_SESSION_COOKIE_NAME, value, **IDP_SESSION_COOKIE)
    return response


def clear_idp_session_cookie(response):
    response.delete_cookie(IDP_SESSION_COOKIE_NAME, **IDP_SESSION_COOKIE)
    return response


# Backwards-compatible names while the cookie itself remains wos_session.
WOS_SESSION_COOKIE = IDP_SESSION_COOKIE
set_wos_session_cookie = set_idp_session_cookie
clear_wos_session_cookie = clear_idp_session_cookie
