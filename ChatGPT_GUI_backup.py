import tkinter as tk
import cryptography
from cryptography.fernet import Fernet
import os.path



root = tk.Tk()

root.title ("Password Vault")

def generate_key():
    
    #Generates a key and saves it into a file
    
    key = Fernet.generate_key()
    with open("C:\\Users\\Trainee\Desktop\\Python Projects\\key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    
    #Loads the key from the current directory named `key.key`
    
    return open("C:\\Users\\Trainee\Desktop\\Python Projects\\key.key", "rb").read()

def encrypt_password(password):
    
    #Encrypts a password
    
    key = load_key()
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password):

     #Decrypts a password
    
    key = load_key()
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password


file_path = "C:\\Users\\Trainee\Desktop\\Python Projects\\key.key"
if os.path.exists("C:\\Users\\Trainee\Desktop\\Python Projects\\key.key"):
  file_status = "exists"
    # file exists
    # Do something with the file
else:
  generate_key ()
    # file does not exist
    # Handle the case where the file does not exist


load_key()


def LoginScreen():
    for widget in root.winfo_children():
        widget.destroy()
    root.geometry("400x200")

    lbl = tk.Label(root, text="Welcome to the password manager.", anchor = "center")
    lbl.grid(row=0, column=2, pady=10)

    def Add_Password():
        for widget in root.winfo_children():
            widget.destroy()
        root.geometry("400x200")

        lbl1 = tk.Label(root, width=15, text="Enter Website:")
        lbl1.grid(row=1, column=0, sticky="w", padx=10, pady=5)

        txt1 = tk.Entry(root, width=15)
        txt1.grid(row=1, column=1, pady=5)

        lbl2 = tk.Label(root, width=15, text="Enter Username:")
        lbl2.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        txt2 = tk.Entry(root, width=15, )
        txt2.grid(row=2, column=1, pady=5)

        lbl3 = tk.Label(root, width=15, text="Enter Password:")
        lbl3.grid(row=3, column=0, sticky="w", padx=10, pady=5)

        txt3 = tk.Entry(root, width=15, show="*")
        txt3.grid(row=3, column=1, pady=5)

        def save_password(txt1, txt2, txt3):
            username = txt1.get()
            service = txt2.get()
            password = txt3.get()

        #Adds a new password for a service and username to the password file
    
            encrypted_password = encrypt_password(password)
            with open("C:\\Users\\Trainee\\Desktop\\Python Projects\\passwords.txt", "a") as password_file:
                password_file.write(f"{service},{username},{encrypted_password.decode()}\n")
                    # Return to the LoginScreen
            LoginScreen()

        btn_save = tk.Button(root, text="Save", command= lambda: save_password(txt1, txt2, txt3), width=15)
        btn_save.grid(row=4, column=1, pady=10)

    def Retrieve_Password():
        for widget in root.winfo_children():
            widget.destroy()
        root.geometry("400x200")

        r_lbl1 = tk.Label(root, width=15, text="Enter Website:")
        r_lbl1.grid(row=1, column=0, sticky="w", padx=10, pady=5)

        r_txt1 = tk.Entry(root, width=15)
        r_txt1.grid(row=1, column=1, pady=5)

        r_lbl2 = tk.Label(root, width=15, text="Enter Username:")
        r_lbl2.grid(row=2, column=0, sticky="w", padx=10, pady=5)

        r_txt2 = tk.Entry(root, width=15)
        r_txt2.grid(row=2, column=1, pady=5)

        

    btn_add = tk.Button(root, text="Add Password", command=Add_Password, width=15)
    btn_add.grid(row=1, column=2, padx=10, pady=5)

    btn_retrieve = tk.Button(root, text="Retrieve Password", command="", width=15)
    btn_retrieve.grid(row=2, column=2, padx=10, pady=5)

    btn_exit = tk.Button(root, text="Exit", command="", width=15)
    btn_exit.grid(row=3, column=2, padx=10, pady=5)

LoginScreen()
root.mainloop()