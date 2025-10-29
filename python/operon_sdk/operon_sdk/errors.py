class OperonError(Exception):
    """Base error for the Operon SDK."""


class ValidationError(OperonError):
    """Raised when client-side validation fails."""


class TransportError(OperonError):
    """Wraps transport-level failures when calling Operon services."""

    def __init__(self, message: str, *, original: Exception | None = None) -> None:
        super().__init__(message)
        self.original = original


class ApiError(OperonError):
    """Represents an error returned by Operon APIs."""

    def __init__(self, status_code: int, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
