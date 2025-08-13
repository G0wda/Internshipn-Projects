import re

def check_password_strength(password):
    strength_points = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        strength_points += 2
    elif len(password) >= 8:
        strength_points += 1
    else:
        feedback.append("Password is too short (use at least 12 characters).")

    # Uppercase check
    if re.search(r"[A-Z]", password):
        strength_points += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    # Lowercase check
    if re.search(r"[a-z]", password):
        strength_points += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    # Digit check
    if re.search(r"\d", password):
        strength_points += 1
    else:
        feedback.append("Add at least one number.")

    # Special character check
    if re.search(r"[@$!%*?&]", password):
        strength_points += 1
    else:
        feedback.append("Add at least one special character (@, $, !, %, *, ?, &).")

    # Common password check
    common_passwords = ["password", "123456", "qwerty", "letmein", "admin", "welcome"]
    if password.lower() in common_passwords:
        feedback.append("Avoid using common or easily guessable passwords.")

    # Final strength rating
    if strength_points >= 7:
        strength = "Strong"
    elif 4 <= strength_points < 7:
        strength = "Medium"
    else:
        strength = "Weak"

    return strength, feedback


if __name__ == "__main__":
    print("Password Strength Checker")
    user_password = input("Enter a password to evaluate: ")

    strength, recommendations = check_password_strength(user_password)
    print(f"\nPassword Strength: {strength}")

    if recommendations:
        print("\nRecommendations to improve:")
        for rec in recommendations:
            print(rec)
    else:
        print("Your password meets all best practices!")
