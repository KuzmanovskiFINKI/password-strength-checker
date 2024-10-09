import unittest
from src.password_checker import check_password_strength, load_common_passwords, provide_feedback


class TestPasswordStrengthChecker(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Load common passwords for testing
        cls.common_passwords = load_common_passwords('../common_passwords.txt')

    def test_strong_password(self):
        password = "StrongP@ssword123!"
        expected_strength = "Very Strong (Entropy: 115.06 bits)"
        self.assertEqual(check_password_strength(password, self.common_passwords), expected_strength)

    def test_common_password(self):
        password = "password1"
        expected_strength = "Very Weak (Common Password)"
        self.assertEqual(check_password_strength(password, self.common_passwords), expected_strength)

    def test_weak_password(self):
        password = "weakpass"
        expected_strength = "Weak (Entropy: Too short)"
        self.assertEqual(check_password_strength(password, self.common_passwords), expected_strength)

    def test_missing_uppercase(self):
        password = "lowercase123!"
        expected_strength = "Weak (Entropy: 76.15 bits)"
        self.assertEqual(check_password_strength(password, self.common_passwords), expected_strength)

    def test_missing_digit(self):
        password = "MissingDigit!"
        expected_strength = "Weak (Entropy: 80.72 bits)"
        self.assertEqual(check_password_strength(password, self.common_passwords), expected_strength)

    def test_missing_special_char(self):
        password = "NoSpecialChar1"
        expected_strength = "Weak (Entropy: 83.36 bits)"
        self.assertEqual(check_password_strength(password, self.common_passwords), expected_strength)

    def test_length_too_short(self):
        password = "Short1!"
        expected_strength = "Weak (Entropy: Too short)"
        self.assertEqual(check_password_strength(password, self.common_passwords), expected_strength)

    def test_feedback(self):
        password = "weakpass"
        expected_feedback = [
            "Password should be at least 12 characters long.",
            "Add uppercase letters for better security.",
            "Include at least one digit.",
            "Include special characters like !@#$%^&*()"
        ]
        self.assertEqual(provide_feedback(password), expected_feedback)


if __name__ == "__main__":
    unittest.main()
