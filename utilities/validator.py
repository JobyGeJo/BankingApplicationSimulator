import re

class Validator:

    def validate_email(self, email: str) -> bool:
        pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
        return 2 < len(email) < 320 and bool(re.match(pattern, email))

    def validate_name(self, name: str) -> bool:
        pattern = r"^[A-Za-z ]+$"
        print(name, bool(re.match(pattern, name)))
        return bool(re.match(pattern, name))

    def validate_length(self, variable: str, min_length: int=0, max_length: int=100) -> bool:
        return min_length <= len(variable) <= max_length

    def validate_phone_no(self, variable: str) -> bool:
        pattern = r"^[1-9]+[0-9]{9}$"
        return bool(re.match(pattern, str(variable)))
    