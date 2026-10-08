import json
import string
import secrets
import hashlib


class PasswordManager:

    PASSWORD_FILE = "Passwords.json"
    MASTER_PASSWORD_FILE = "Master_password.json"

    def __init__(self):
        self.passwords = self.load_passwords()
        self.master_data = self.load_master_password()

    # -------------------- FILE HANDLING --------------------

    def load_passwords(self):
        try:
            with open(self.PASSWORD_FILE, "r") as file:
                return json.load(file)

        except FileNotFoundError:
            return {}

        except json.JSONDecodeError:
            print("⚠️ Passwords.json is corrupted.")
            return {}

    def save_passwords(self):
        with open(self.PASSWORD_FILE, "w") as file:
            json.dump(self.passwords, file, indent=4)

    def load_master_password(self):
        try:
            with open(self.MASTER_PASSWORD_FILE, "r") as file:
                return json.load(file)

        except FileNotFoundError:
            return None

        except json.JSONDecodeError:
            print("⚠️ Master_password.json is corrupted.")
            return None

    # -------------------- PASSWORD SECURITY --------------------

    def hash_password(self, password, salt):
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            100_000
        ).hex()

    # -------------------- MASTER PASSWORD --------------------

    def create_master_password(self):
        while True:
            password = input("Create Master Password: ")

            if not password:
                print("❌ Master password cannot be empty.")
                continue

            if len(password) < 4:
                print("❌ Master password must contain at least 4 characters.")
                continue

            break

        salt = secrets.token_bytes(16)

        password_hash = self.hash_password(password, salt)

        self.master_data = {
            "salt": salt.hex(),
            "password_hash": password_hash
        }

        with open(self.MASTER_PASSWORD_FILE, "w") as file:
            json.dump(self.master_data, file, indent=4)

        print("Master Password created successfully ✅")

    def verify_master_password(self):
        password = input("Enter Master Password: ")

        try:
            salt = bytes.fromhex(self.master_data["salt"])

            password_hash = self.hash_password(
                password,
                salt
            )

            if password_hash == self.master_data["password_hash"]:
                print("Access Granted ✅")
                return True

            print("Incorrect Master Password ❌")
            return False

        except (KeyError, ValueError):
            print("❌ Invalid master password data.")
            return False

    # -------------------- WEBSITE VALIDATION --------------------

    def get_valid_site(self):
        site = input("Enter the website: ").strip().lower()

        if not site:
            print("❌ Website cannot be empty.")
            return None

        if "." not in site:
            print("❌ Please enter a valid domain, e.g. google.com")
            return None

        return site

    # -------------------- ADD PASSWORD --------------------

    def add_password(self):
        site = self.get_valid_site()

        if site is None:
            return

        if site in self.passwords:
            print(f"❌ Password for {site} already exists.")
            return

        password = input("Enter the password: ")

        if not password:
            print("❌ Password cannot be empty.")
            return

        self.passwords[site] = password
        self.save_passwords()

        print(f"✅ Password for {site} saved successfully.")

    # -------------------- VIEW PASSWORDS --------------------

    def view_passwords(self):
        if not self.passwords:
            print("No passwords are saved.")
            return

        print("\n---- Saved Passwords ----")

        for site, password in self.passwords.items():
            print(f"{site} : {password}")

    # -------------------- SEARCH PASSWORD --------------------

    def search_password(self):
        site = self.get_valid_site()

        if site is None:
            return

        if site in self.passwords:
            print(f"Website : {site}")
            print(f"Password: {self.passwords[site]}")
        else:
            print("❌ Password not found.")

    # -------------------- UPDATE PASSWORD --------------------

    def update_password(self):
        site = self.get_valid_site()

        if site is None:
            return

        if site not in self.passwords:
            print("❌ Website not found.")
            return

        new_password = input("Enter new password: ")

        if not new_password:
            print("❌ Password cannot be empty.")
            return

        self.passwords[site] = new_password
        self.save_passwords()

        print("✅ Password updated successfully.")

    # -------------------- DELETE PASSWORD --------------------

    def delete_password(self):
        site = self.get_valid_site()

        if site is None:
            return

        if site not in self.passwords:
            print("❌ Website not found.")
            return

        confirmation = input(
            f"Are you sure you want to delete {site}? (y/n): "
        ).strip().lower()

        if confirmation == "y":
            del self.passwords[site]
            self.save_passwords()

            print("✅ Website deleted successfully.")

        else:
            print("❌ Delete operation cancelled.")

    # -------------------- PASSWORD GENERATOR --------------------

    def generate_password(self):
        characters = (
            string.ascii_letters
            + string.digits
            + "!@#$%^&*"
        )

        password = "".join(
            secrets.choice(characters)
            for _ in range(12)
        )

        print(f"Generated Password: {password}")

    # -------------------- MENU --------------------

    def menu(self):

        while True:

            print("\n" + "=" * 35)
            print("       🔐 PASSWORD MANAGER")
            print("=" * 35)

            print("1. Add Password")
            print("2. View Passwords")
            print("3. Generate Password")
            print("4. Search Password")
            print("5. Update Password")
            print("6. Delete Password")
            print("7. Exit")

            try:
                choice = int(input("\nEnter your choice: "))

            except ValueError:
                print("❌ Please enter a number.")
                continue

            if choice == 1:
                self.add_password()

            elif choice == 2:
                self.view_passwords()

            elif choice == 3:
                self.generate_password()

            elif choice == 4:
                self.search_password()

            elif choice == 5:
                self.update_password()

            elif choice == 6:
                self.delete_password()

            elif choice == 7:
                print("Exiting Password Manager... 👋")
                break

            else:
                print("❌ Invalid choice. Please select 1-7.")


# -------------------- PROGRAM START --------------------

manager = PasswordManager()

if manager.master_data is None:

    print("\n🔐 Welcome to Password Manager")
    print("Create your Master Password.")

    manager.create_master_password()
    manager.menu()

else:

    if manager.verify_master_password():
        manager.menu()

    else:
        print("Access Denied ❌")