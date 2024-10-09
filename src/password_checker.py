import re
import math

# List of special characters to check
special_characters = r'[!@#$%^&*(),.?":{}|<>]'


def load_common_passwords(filename):
    """ Load common passwords from a file into a set """
    with open(filename, 'r') as file:
        return {line.strip() for line in file}


def check_password_strength(password, common_passwords):
    """ Evaluates the strength of a given password """
    if password in common_passwords:
        return "Very Weak (Common Password)"

    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(special_characters, password))

    # Calculate entropy
    entropy = calculate_entropy(password)

    # Password strength criteria
    if length < 12:
        return "Weak (Entropy: Too short)"
    if not (has_upper and has_lower and has_digit and has_special):
        return f"Weak (Entropy: {entropy:.2f} bits)"

    # Define strength based on entropy
    if entropy < 40:
        return f"Weak (Entropy: {entropy:.2f} bits)"
    elif 40 <= entropy < 60:
        return f"Moderate (Entropy: {entropy:.2f} bits)"
    elif 60 <= entropy < 80:
        return f"Strong (Entropy: {entropy:.2f} bits)"
    else:
        return f"Very Strong (Entropy: {entropy:.2f} bits)"


def calculate_entropy(password):
    """ Calculate password entropy based on the character set size """
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
        # print(f"DEBUG: Lowercase letters found. Charset size: {charset_size}")
    if re.search(r'[A-Z]', password):
        charset_size += 26
        # print(f"DEBUG: Uppercase letters found. Charset size: {charset_size}")
    if re.search(r'\d', password):
        charset_size += 10
        # print(f"DEBUG: Digits found. Charset size: {charset_size}")
    if re.search(special_characters, password):
        charset_size += len(special_characters)
        # print(f"DEBUG: Special characters found. Charset size: {charset_size}")

    entropy = math.log2(charset_size ** len(password))
    # print(f"DEBUG: Password length: {len(password)}, Entropy: {entropy}")
    return entropy


def provide_feedback(password):
    """ Provide user-friendly feedback on how to improve password strength """
    feedback = []

    if len(password) < 12:
        feedback.append("Password should be at least 12 characters long.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Add uppercase letters for better security.")
    if not re.search(r'[a-z]', password):
        feedback.append("Add lowercase letters for better security.")
    if not re.search(r'\d', password):
        feedback.append("Include at least one digit.")
    if not re.search(special_characters, password):
        feedback.append("Include special characters like !@#$%^&*()")

    return feedback


# Main program for interactive use
if __name__ == "__main__":
    common_passwords = load_common_passwords('../common_passwords.txt')
    password = input("Enter a password to check: ")
    strength = check_password_strength(password, common_passwords)
    feedback = provide_feedback(password)

    print(f"Password strength: {strength}")
    if feedback:
        print("Suggestions to improve your password:")
        for tip in feedback:
            print(f"- {tip}")
