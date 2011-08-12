class ApiError(Exception):
    pass


class ApiServerError(ApiError):
    pass


class ApiClientError(ApiError):
    pass


class InvalidConsumer(ApiServerError):
    pass


class InvalidVerifier(ApiServerError):
    pass


class RequestTokenExpired(ApiServerError):
    pass


class AccessTokenExpired(ApiServerError):
    pass


class AccessDenied(ApiServerError):
    pass


class XAuthNotAllowed(ApiServerError):
    """ Application is not allowed to use the xAuth extension.
        Send a request to info@mobilevikings.com if you need
        this feature.
    """
    pass


class XAuthAccessDenied(ApiServerError):
    """ Username/password combination is incorrect. """
    pass


class MissingParameters(ApiServerError):
    pass


class InvalidMethod(ApiServerError):
    pass
