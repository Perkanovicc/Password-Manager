from doctest import master
from os.path import expanduser
import tkinter
import os
key_file_path = 'encryption_key.key'

def generate_key():
    key = Fernet.generate_key()
    with open(key_file_path, 'wb') as key_file:
        key_file.write(key)
    return key

def ucitaj_kljuc():
    if os.path.exists(key_file_path):
        with open(key_file_path, 'rb') as key_file:
            key = key_file.read()
    else:
        print("Key file not found. Generating a new key...")
        key = generate_key()
    return key

from cryptography.fernet import Fernet
import customtkinter
MASTERPW="Test123"

def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)

    window.geometry(f'{width}x{height}+{x}+{y}')
def validate_password():
    user_input = entry.get()
    if user_input == MASTERPW:
        frame.pack_forget()
        frame3.pack_forget()
        frame4.pack_forget()
        frame2.pack(pady=10,padx=10,fill="both",expand=True)
        entry.delete(0,tkinter.END)
        label2.configure(text="")
    else:
        label2.configure(text="Incorrect password.")
def showFrame3():
    frame2.pack_forget()
    frame3.pack(pady=10, padx=10, fill="both", expand=True)
def showFrame4():
    frame2.pack_forget()
    frame4.pack(pady=10, padx=10, fill="both", expand=True)
def prikaziSifru():
    if checkbox_var.get():
        entry3.configure(show="")
    else:
        entry3.configure(show="*")
def add():
    username=entry2.get()
    password=entry3.get()
    kljuc = ucitaj_kljuc()
    fernet = Fernet(kljuc)
    sifra_enkriptovana = fernet.encrypt(password.encode())
    with open('db.txt', 'a') as fajl:
        fajl.write(f"{username}|{sifra_enkriptovana.decode()}\n")
    entry2.delete(0, tkinter.END)
    entry3.delete(0, tkinter.END)
    entry2.focus_set()
def listing():
    username=entry4.get()
    with open("db.txt", "r") as fajl:
        for linija in fajl:
            korisnicko_ime, sifra_enkriptovana = linija.strip().split("|")
            if korisnicko_ime == username:
                sifra = dekriptuj_sifru(sifra_enkriptovana.encode())
                label6.configure(text=f"{korisnicko_ime}  |  {sifra}")
                entry4.delete(0, tkinter.END)
def dekriptuj_sifru(sifra_enkriptovana):
    kljuc = ucitaj_kljuc()
    fernet = Fernet(kljuc)
    sifra_dekriptovana = fernet.decrypt(sifra_enkriptovana).decode()
    return sifra_dekriptovana
def drugiUPrvi():
    frame2.pack_forget()
    frame.pack(padx=10,pady=12,fill="both",expand=True)
def treciUDrugi():
    frame3.pack_forget()
    frame2.pack(padx=10, pady=12, fill="both", expand=True)
def cetvrtiUDrugi():
    frame4.pack_forget()
    frame2.pack(padx=10, pady=12, fill="both", expand=True)
    label6.configure(text="")
def on_closing():
    root.destroy()
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("green")

root=customtkinter.CTk()
root.geometry("500x350")
root.title("Password Manager")

center_window(root,600,400)

root.protocol("WM_DELETE_WINDOW", on_closing)

frame=customtkinter.CTkFrame(master=root)
frame.pack(pady=10, padx=10, fill="both", expand=True)

label=customtkinter.CTkLabel(master=frame, text="Enter Master Password",font=("Roboto",24))
label.pack(pady=12, padx=10)

entry=customtkinter.CTkEntry(master=frame, placeholder_text="Master Password", show="*",width=200)
entry.pack(pady=12,padx=10)

button=customtkinter.CTkButton(master=frame, text="Login as Master",command=validate_password)
button.pack()

label2=customtkinter.CTkLabel(master=frame, text="",font=("Roboto",14),text_color="red")
label2.pack(padx=10,pady=12)

frame3=customtkinter.CTkFrame(master=root)

backButton32 = customtkinter.CTkButton(frame3, text="<-",width=30, command=treciUDrugi)
backButton32.pack(anchor='w', padx=7, pady=(7, 0))

label4=customtkinter.CTkLabel(master=frame3, text="Add an username and password to asign to it.",font=("Roboto",24))
label4.pack(padx=10,pady=12)

entry2=customtkinter.CTkEntry(master=frame3,placeholder_text="Username", width=200)
entry2.pack(padx=10,pady=12)

entry3=customtkinter.CTkEntry(master=frame3,placeholder_text="Password", width=200,show="*")
entry3.pack(padx=10,pady=12)

checkbox_var=customtkinter.BooleanVar()

checkbox=customtkinter.CTkCheckBox(master=frame3, text="Show Password",variable=checkbox_var,command=prikaziSifru)
checkbox.pack(padx=10,pady=12)

button4=customtkinter.CTkButton(master=frame3,text="Add",command=add)
button4.pack(padx=10,pady=12)
frame2=customtkinter.CTkFrame(master=root)

backButton21 = customtkinter.CTkButton(frame2, text="<-",width=30,command=drugiUPrvi)
backButton21.pack(anchor='w', padx=7, pady=(7, 0))

label3=customtkinter.CTkLabel(master=frame2, text="Do you want to add or to list existing password?",font=("Roboto",24))
label3.pack(padx=10,pady=12)
button2=customtkinter.CTkButton(master=frame2, text="Add Password",command=showFrame3)
button2.pack(padx=10,pady=12)

frame4=customtkinter.CTkFrame(master=root)

backButton42 = customtkinter.CTkButton(frame4, text="<-",width=30,command=cetvrtiUDrugi)
backButton42.pack(anchor='w', padx=7, pady=(7, 0))

label5=customtkinter.CTkLabel(master=frame4, text="Type username you want to show password for.", font=("Roboto",24))
label5.pack(padx=10,pady=12)

entry4=customtkinter.CTkEntry(master=frame4, placeholder_text="Username", width=200)
entry4.pack(padx=10,pady=12)

button5=customtkinter.CTkButton(master=frame4,text="List", command=listing)
button5.pack(padx=10,pady=12)

label6=customtkinter.CTkLabel(master=frame4, text="",text_color="white")
label6.pack(padx=10,pady=12)

button3=customtkinter.CTkButton(master=frame2, text="List Password",command=showFrame4)
button3.pack(padx=10,pady=12)

root.mainloop()

def generisi_kljuc():
    kljuc = Fernet.generate_key()
    with open("encryption_key.key", "wb") as fajl:
        fajl.write(kljuc)
def ucitaj_kljuc():
    with open("encryption_key.key", "rb") as fajl:
        return fajl.read()
def dekriptuj_sifru(sifra_enkriptovana):
    kljuc = ucitaj_kljuc()
    fernet = Fernet(kljuc)
    sifra_dekriptovana = fernet.decrypt(sifra_enkriptovana).decode()
    return sifra_dekriptovana