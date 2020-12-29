class ExpiredError(Exception):
    """
    Raise when item is expired.
    """

class InvalidKeyError(Exception):
    """
    Raise when trying to authenticate with an unknown/invalid key.
    """

class InvalidTokenError(Exception):
    """
    Raise when trying to use an unknown/invalid token.
    """

class RefreshError(Exception):
    """
    Raise when refreshing JWT fails.
    """

class AuthenticationError(Exception):
    """
    Raise when failed to authenticate.
    """

class MissingCredentialsError(Exception):
    """
    Raise when no credentials were given to Client class.
    """

class InvalidServerURLError(Exception):
    """
    Raised if an invalid server URL is given.
    """

class RegisterKeyError(Exception):
    """
    Raised when failed to register key to server.
    """

class IsKeyRegisteredError(Exception):
    """
    Raised when failed to check if key is registered.
    """

class MissingAuthorizationError(Exception):
    """
    Raised when authorization header is missing from request.
    """

class BadAuthorizationError(Exception):
    """
    Raised when authorization header is incorrect.
    """

class MissingJWTError(Exception):
    """
    Raised if JWT is misisng.
    """
