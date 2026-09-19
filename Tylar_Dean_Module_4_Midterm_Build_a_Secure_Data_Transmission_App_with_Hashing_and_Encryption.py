import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --------------------
# USER ACCOUNTS / ROLES
# --------------------

USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin"
    },

    "user": {
        "password": "user123",
        "role": "user"
    }
}

# Stores information about the currently logged in user

current_user = None
current_role = None


# --------------------
# ENCRYPTION SETUP
# --------------------

# Generate a secure 256-bit AES key
key = AESGCM.generate_key(bit_length=256)
aes = AESGCM(key)

# Variables used to store information
original_hash = ""
encrypted_message = None
nonce = None




# --------------------
# FUNCTIONS
# --------------------

def login():
    global current_user, current_role

    username = username_entry.get(). strip()
    password = password_entry.get()

    # Check username and password
    if username in USERS and USERS[username]["password"] == password:

        current_user = username
        current_role = USERS[username]["role"]

        messagebox.showinfo(
            "Login Successful",
            f"Welcome {current_user}!\nRole: {current_role}"
        )

        # Hide login screen
        login_frame.pack_forget()

        #Show main security application
        main_frame.pack(pady=10)

        # Display logged in user and role
        user_status.config(
            text=f"Logged in as: {current_user} | Role: {current_role}"
        )

    else:

        messagebox.showerror(
            "Login Failed",
            "Invalid username or password."
        )


def logout():
    global current_user, current_role
    global original_hash, encrypted_message, nonce

    # Remove information about the logged in user
    current_user = None
    current_role = None

    # Clear stored encryption information
    original_hash = ""
    encrypted_message = None
    nonce = None

    # Clear the message input
    message_entry.delete("1.0", tk.END)

    # Clear SHA-256 hash output
    hash_output.config(state="normal")
    hash_output.delete("1.0", tk.END)
    hash_output.config(state="disabled")

    # Clear encrypted message output
    encrypted_output.config(state="normal")
    encrypted_output.delete("1.0", tk.END)
    encrypted_output.config(state="disabled")

    # Clear decrypted message output
    decrypted_output.config(state="normal")
    decrypted_output.delete("1.0", tk.END)
    decrypted_output.config(state="disabled")

    # Clear verification result
    verification_label.config(text="")

    # Clear user status
    user_status.config(text="")

    # Clear login fields
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

    # Hide main application
    main_frame.pack_forget()

    # Show login screen again
    login_frame.pack(pady=80)


def generate_hash():
    global original_hash

    message = message_entry.get("1.0", tk.END).strip()

    if not message:
        messagebox.showwarning(
            "Warning",
            "Please enter a message."
        )
        return

    # Create SHA-256 hash
    original_hash = hashlib.sha256(
        message.encode()
    ).hexdigest()

    # Display the hash
    hash_output.config(state="normal")
    hash_output.delete("1.0", tk.END)
    hash_output.insert(tk.END, original_hash)
    hash_output.config(state="disabled")

def encrypt_message():
    global encrypted_message, nonce

    message = message_entry.get("1.0", tk.END).strip()

    if not message:
        messagebox.showwarning(
            "Warning",
            "Please enter a message."
        )
        return

    if not original_hash:
        messagebox.showwarning(
            "Warning",
            "Generate the SHA-256 hash first."
        )
        return

    # Generate a random nonce for AES encryption
    nonce = os.urandom(12)

    # Encrypt the message
    encrypted_message = aes.encrypt(
        nonce,
        message.encode(),
        None
    )

    # Convert encrypted bytes into readable Base64
    readable_encrypted = base64.b64encode(
        encrypted_message
    ).decode()

    # Display encrypted message
    encrypted_output.config(state="normal")
    encrypted_output.delete("1.0", tk.END)
    encrypted_output.insert(
        tk.END,
        readable_encrypted
    )
    encrypted_output.config(state="disabled")

def decrypt_and_verify():

    # --------------------
    # ROLE BASED ACCESS CONTROL
    # --------------------

    # Only administrators can decrypt and verify messages
    if current_role != "admin":

        messagebox.showerror(
            "Access Denied",
            "Only administrators can decrypt and verify messages."
        )

        return


    if encrypted_message is None or nonce is None:
        messagebox.showwarning(
            "Warning",
            "Please encrypt a message first."
        )
        return

    try:

        # Decrypt the encrypted message
        decrypted_bytes = aes.decrypt(
            nonce,
            encrypted_message,
            None
        )

        decrypted_message = decrypted_bytes.decode()

        # Create a new SHA-356 hash
        decrypted_hash = hashlib.sha256(
            decrypted_message.encode()
        ).hexdigest()

        # Display decrypted message
        decrypted_output.config(state="normal")
        decrypted_output.delete("1.0", tk.END)
        decrypted_output.insert(
            tk.END,
            decrypted_message
        )
        decrypted_output.config(state="disabled")

        # Compare the original hash with the decrypted hash
        if decrypted_hash == original_hash:

            verification_label.config(
                text="Integrity Verified",
                fg="#FFE868"
            )

        else:

            verification_label.config(
                text="Integrity verification failed",
                fg="white"
            )

    except Exception:

        messagebox.showerror(
            "Error",
            "The message could not be decrypted."
        )



# --------------------
# GUI WINDOW
# --------------------


root = tk.Tk()

root.title("Message Security Tool")
root.geometry("750x800")

# Black Background
root.configure(bg="black")




# --------------------
# TOP HEADER
# --------------------

header_frame = tk.Frame(
    root,
    bg="black",
    height=90
)

header_frame.pack(fill="x")

title_label = tk.Label(
    header_frame,
    text="Message Security Tool",
    font=("Arial", 28, "bold"),
    bg="black",
    fg="#58CDFF"
)

title_label.pack(pady=22)


# --------------------
# LOGIN SCREEN
# --------------------

login_frame = tk.Frame(
    root,
    bg="black"
)

login_frame.pack(pady=80)

login_title = tk.Label(
    login_frame,
    text="Secure Login",
    font=("Arial", 24, "bold"),
    bg="black",
    fg="#FFE868"
)

login_title.pack(pady=15)

username_label = tk.Label(
    login_frame,
    text="Username:",
    font=("Arial", 12, "bold"),
    bg="black",
    fg="white"
)

username_label.pack()

username_entry = tk.Entry(
    login_frame,
    width=30,
    font=("Arial", 12)
)

username_entry.pack(pady=5)

password_label = tk.Label(
    login_frame,
    text="Password:",
    font=("Arial", 12, "bold"),
    bg="black",
    fg="white"
)

password_label.pack(pady=(10, 0))

password_entry = tk.Entry(
    login_frame,
    width=30,
    show="*",
    font=("Arial", 12)
)

password_entry.pack(pady=5)

login_button = tk.Button(
    login_frame,
    text="Login",
    command=login,
    bg="#58CDFF",
    fg="black",
    font=("Arial", 11, "bold"),
    width=20
)

login_button.pack(pady=20)


# --------------------
# MAIN CONTENT
# --------------------

main_frame = tk.Frame(
    root,
    bg="black"
)


# --------------------
# USER / ROLE STATUS
# --------------------

user_status = tk.Label(
    main_frame,
    text="",
    font=("Arial", 10, "bold"),
    bg="black",
    fg="#FFE868"
)

user_status.pack(pady=5)

# --------------------
# LOGOUT BUTTON
# --------------------

logout_button = tk.Button(
    main_frame,
    text="Logout",
    command=logout,
    bg="#FFE868",
    fg="black",
    font=("Arial", 10, "bold"),
    width=12
)

logout_button.pack(pady=5)

# --------------------
# MESSAGE SECTION
# --------------------

message_label = tk.Label(
    main_frame,
    text="Enter Your Message:",
    font=("Arial", 13, "bold"),
    bg="black",
    fg="white"
)

message_label.pack()

message_entry = tk.Text(
    main_frame,
    height=4,
    width=70,
    bg="white",
    fg="black",
    insertbackground="black",
    font=("Arial", 10)
)

message_entry.pack(pady=5)




# --------------------
# HASH SECTION
# --------------------

hash_button = tk.Button(
    main_frame,
    text="Generate SHA-256 Hash",
    command=generate_hash,
    bg="#58CDFF",
    fg="black",
    font=("Arial", 11, "bold"),
    width=25
)

hash_button.pack(pady=10)

hash_label = tk.Label(
    main_frame,
    text="SHA-256 Hash:",
    bg="black",
    fg="white",
    font=("Arial", 11, "bold")
)

hash_label.pack()

hash_output = tk.Text(
    main_frame,
    height=3,
    width=70,
    state="disabled",
    bg="white",
    fg="black",
    font=("Arial", 10)
)

hash_output.pack(pady=5)



# --------------------
# ENCRYPTION SECTION
# --------------------

encrypt_button = tk.Button(
    main_frame,
    text="Encrypt Message",
    command=encrypt_message,
    bg="#58CDFF",
    fg="black",
    font=("Arial", 11, "bold"),
    width=25
)

encrypt_button.pack(pady=10)

encrypted_label = tk.Label(
    main_frame,
    text="Encrypted Message:",
    bg="black",
    fg="white",
    font=("Arial", 11, "bold")
)

encrypted_label.pack()

encrypted_output = tk.Text(
    main_frame,
    height=4,
    width=70,
    state="disabled",
    bg="white",
    fg="black",
    font=("Arial", 10)
)

encrypted_output.pack(pady=5)



# --------------------
# DECRYPTION SECTION
# --------------------

decrypt_button = tk.Button(
    main_frame,
    text="Decrypt & Verify",
    command=decrypt_and_verify,
    bg="#58CDFF",
    fg="black",
    font=("Arial", 11, "bold"),
    width=25
)

decrypt_button.pack(pady=10)

decrypted_label = tk.Label(
    main_frame,
    text="Decrypted Message:",
    bg="black",
    fg="white",
    font=("Arial", 11, "bold")
)

decrypted_label.pack()

decrypted_output = tk.Text(
    main_frame,
    height=4,
    width=70,
    state="disabled",
    bg="white",
    fg="black",
    font=("Arial", 10)
)

decrypted_output.pack(pady=5)



# --------------------
# VERICATION RESULT
# --------------------

verification_label = tk.Label(
    main_frame,
    text="",
    font=("Arial", 17, "bold"),
    bg="black",
    fg="#FFE868"
)

verification_label.pack(pady=20)



# --------------------
# START PROGRAM
# --------------------

root.mainloop()
