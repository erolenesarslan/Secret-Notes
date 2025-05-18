# 🔐 Secret Notes - Encrypted Note-Taking App

**Secret Notes** is a simple desktop application developed using Python and Tkinter. It allows users to securely encrypt their private notes and store them safely, and decrypt them when needed using the correct key.

---

## 📌 Description

This is a basic desktop application written in Python that allows users to:

- Save secret notes
- Encrypt each note with a master key
- Store encrypted notes in a local text file
- Decrypt and view notes using the correct master key

The encryption is done using the `cryptography` library (Fernet symmetric encryption). All notes are stored securely, and only retrievable with the correct master password.

---


## 🛠️ Technologies Used

- Python 3
- Tkinter (GUI)
- Cryptography (Fernet)
- PIL / Pillow (Image support)

---

## 📦 Installation

```bash
pip install cryptography pillow
