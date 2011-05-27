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
