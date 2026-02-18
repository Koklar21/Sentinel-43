class AuthenticationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


class InvalidTokenError(AuthenticationError):
    pass


class ExpiredTokenError(AuthenticationError):
    pass