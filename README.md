# Password-Manager
Encrypted Password Manager
==========================

A simple desktop application for storing your passwords, built with Python. All passwords are stored locally and encrypted using AES encryption.

How It Works
------------

1. **First Launch:**
   - The app will ask you to enter a *master password*.
   - Master password is "Test123".
   - This master password is used to unlock your vault and must be remembered — without it, you cannot access your saved passwords.

2. **After Setup:**
   - Every time you start the app, it will prompt you to enter the master password to decrypt the data.

3. **What You Can Do:**
   - Add new passwords (username, password).
   - View and copy your saved passwords.

Running the App
---------------

1. **Clone the Repository:**

```
git clone https://github.com/Perkanovicc/Password-Manager.git
cd Password-Manager
```

2. **Install Dependencies:**

```
pip install cryptography
```

3. **Run the Application:**

```
python main.py
```

> If you don’t have Python installed, you can create a `.exe` file using PyInstaller (contact the author for help if needed).

Important Notes
---------------

- All passwords are stored **locally** — no internet, no cloud storage.
- If you forget your **master password**, there is no way to recover your data.
- This is an educational project but can be used for personal purposes.

Author: @Perkanovicc (https://github.com/Perkanovicc)
