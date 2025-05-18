import base64, os
from tkinter import *
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

SALT = b"1234567890abcdef"

def derive_key_from_password(password, salt = SALT):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

#Screen
window = Tk()
window.geometry("400x780")
window.title("Secret Notes")
window.resizable(0, 0)

#İmage
image = Image.open("unnamed.png")
resized_image = image.resize((150, 150))
img = ImageTk.PhotoImage(resized_image)
label = Label(image=img)
label.image = img
label.pack()

#Enter your title label
label1 = Label(window, text="Enter your title", font=("Arial", 18, "bold"))
label1.pack(pady=10)

#Input for title
title_input = Entry(window)
title_input.config(width=40)
title_input.pack()

# Enter your secret label
label2 = Label(window, text="Enter your secret", font=("Arial", 18, "bold"))
label2.pack(pady=10)

# Textbox for note
textbox = Text(window)
textbox.config(width=40, height = 20)
textbox.pack()

# Enter masterkey label
label3 = Label(window, text="Enter master key", font=("Arial", 18, "bold"))
label3.pack(pady=10)

# Input for master key
master_input = Entry(window)
master_input.config(width=40)
master_input.pack()

#Save And Encrypt Method
def save_encrypt():
        title = title_input.get().strip()
        message = textbox.get(1.0, END)
        masterkey = master_input.get()
        if len(title) == 0 or len(message) == 0 or len(masterkey) == 0:
            messagebox.showerror("Error", "Please enter your all information")
            return
        else:
            key = derive_key_from_password(masterkey)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(message.encode())

            with open("mysecret.txt", "a") as file:
                file.write(title + "\n")
                file.write(encrypted.decode() + "\n")
            messagebox.showinfo("Success", "Encrypted Successfully")
            title_input.delete(0, END)
            master_input.delete(0, END)
            textbox.delete("1.0", END)

# Save and Encrypt Button
first_btn = Button(window, text="Save & Encrypt", command=save_encrypt)
first_btn.pack(pady=10)

#Decrypt Method
def decrypt():
    title_to_find = title_input.get().strip()
    masterkey = master_input.get().strip()

    if len(title_to_find) == 0 or len(masterkey) == 0:
        messagebox.showerror("Error", "Please fill both title and master key")
        return

    with open("mysecret.txt", "r") as f:
        lines = f.readlines()

    for i in range(0, len(lines), 2):
        title = lines[i].strip()
        encrypted = lines[i+1].strip()

        if title == title_to_find:
            try:
                key = derive_key_from_password(masterkey)
                fernet = Fernet(key)
                decrypted = fernet.decrypt(encrypted.encode()).decode()
                textbox.delete(1.0, END)
                textbox.insert(END, decrypted)
                messagebox.showinfo("Success", "Decryption successful.")
                return
            except:
                messagebox.showerror("Error", "Wrong master key!")
                return

    messagebox.showerror("Not Found", "Title not found.")


#Decrypt Button
second_btn = Button(window, text="Decrypt", command=decrypt)
second_btn.pack()


window.mainloop()
