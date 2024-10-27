class PullkinError(Exception):
    def __init__(self, message):
        self.message = message


class PullkinResponseError(PullkinError):
    def __init__(self, message):
        super().__init__(message)


class PullkinRegistrationRetriesError(PullkinError):
    def __init__(self, message, errors: list[PullkinResponseError]):
        super().__init__(message)

        self.errors = errors
