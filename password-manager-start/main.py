from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import random
import pyperclip
import json
import requests
import hashlib


# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def generate_password():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v',
               'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
               'R',
               'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    password_list = [random.choice(letters) for _ in range(random.randint(8, 10))]
    password_list += [random.choice(symbols) for _ in range(random.randint(2, 4))]
    password_list += [random.choice(numbers) for _ in range(random.randint(2, 4))]

    random.shuffle(password_list)

    password = "".join(password_list)

    password_entry.delete(0, END)
    password_entry.insert(END, password)
    pyperclip.copy(password)


# ---------------------------- SEARCH JSON ------------------------------- #
def search():
    data_to_search = website_entry.get()
    if len(data_to_search) != 0:
        try:
            with open(file="data.json", mode="r") as data_file:
                data = json.load(data_file)[data_to_search]
        except KeyError:
            messagebox.showerror(title="Error", message=f"No details for {data_to_search} exists!")
        except FileNotFoundError:
            messagebox.showerror(title="Error", message="No Data File Found!")
        else:
            email = data["email"]
            password = data["password"]
            pyperclip.copy(password)
            messagebox.showinfo(title="Result", message=f"Website: {data_to_search}"
                                                        f"\nEmail: {email}\nPassword: {password}\n\n\nPassword copied "
                                                        f"to clipboard.")


# ---------------------------- CHECK PASSWORD PWNED ------------------------------- #
def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    try:
        res = requests.get(url)
    except requests.exceptions.ConnectionError:
        messagebox.showerror(title="Oops!", message="Make sure you have an active internet connection.")
    except Exception:
        messagebox.showerror(title="Oops!", message="Something went wrong!\nTry again later.")
    else:
        return res


def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)


def pwned_main():
    password = password_entry.get()
    if len(password) == 0:
        messagebox.showerror(title="Oops", message="Please enter a password")
    else:
        count = pwned_api_check(password)
        if count:
            message = f'Your password is not safe!\n{password} was found {count} time(s).You should change your ' \
                      f'password. '
            messagebox.showinfo(title="Has your password been pwned?", message=message)

        else:
            message = f'{password} is SAFE to use.Carry on!'
            messagebox.showinfo(title="Has your password been pwned?", message=message)


# ---------------------------- WRITE TO JSON ------------------------------- #
def write_to_json(file, data):
    with open(file=file, mode="w") as data_file:
        json.dump(data, data_file, indent=4)


# ---------------------------- SAVE PASSWORD ------------------------------- #
def save():
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    new_data = {website: {'email': email,
                          'password': password}}
    # checking if any field is empty
    if len(website) == 0 or len(email) == 0 or len(password) == 0:
        messagebox.showerror(title="Oops", message="Please don't leave any fields empty!")
    else:
        # check details entered
        is_ok = messagebox.askokcancel(title="Check Details",
                                       message=f"These are the detailed entered:\nWebsite: {website}\nEmail: {email} "
                                               f"\nPassword: {password}\n Is it ok to save?")
        # saving weather_data to txt file
        if is_ok:
            try:
                with open(file="data.json", mode="r") as data_file:
                    # read json file
                    data = json.load(data_file)
                    # update json file
                    data.update(new_data)
            except json.JSONDecodeError or FileNotFoundError:
                write_to_json(file="data.json", data=new_data)
            else:
                write_to_json(file="data.json", data=data)
            finally:
                website_entry.delete(0, END)
                password_entry.delete(0, END)
                website_entry.focus()


# ---------------------------- SHOW DATA ------------------------------- #

def show_data_popup():
    data_window = Tk()
    data_window.title("Password Data")
    data_window.minsize(width=650, height=200)
    data_window.resizable(0, 0)
    # Create A Main Frame
    main_frame = Frame(data_window)
    main_frame.pack(fill=BOTH, expand=1)

    # Create A Canvas
    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    # Add A Scrollbar To The Canvas
    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    # Configure The Canvas
    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))
    my_canvas.bind_all('<MouseWheel>', lambda event: my_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units"))

    # Create ANOTHER Frame INSIDE the Canvas
    second_frame = Frame(my_canvas)

    # Add that New frame To a Window In The Canvas
    my_canvas.create_window((50, 0), window=second_frame, anchor="nw")
    put_saved_data(second_frame)


def put_saved_data(frame):
    try:
        with open(file="data.json", mode="r") as data_file:
            data = json.load(data_file)
    except FileNotFoundError:
        messagebox.showerror(title="Error", message="No Data File Found!")
    else:
        Label(frame, text="Website", font=('Arial', 12, 'bold')).grid(row=0, column=0, padx=20)
        Label(frame, text="Email", font=('Arial', 12, 'bold')).grid(row=0, column=1, padx=20)
        Label(frame, text="Password", font=('Arial', 12, 'bold')).grid(row=0, column=2, padx=20)
        i = 1
        for key, value in data.items():
            Label(frame, text=f"{key}", font=('Arial', 10, 'normal')).grid(row=i, column=0, padx=20,
                                                                           pady=10)

            Label(frame, text=f"{value['email']}", font=('Arial', 10, 'normal')).grid(row=i, column=1,
                                                                                      padx=20, pady=10)
            Label(frame, text=f"{value['password']}", font=('Arial', 10, 'normal')).grid(row=i,
                                                                                         column=2,
                                                                                         padx=20,
                                                                                         pady=10)

            i += 1


# ---------------------------- UI SETUP ------------------------------- #
# setting window
window = Tk()
window.title("Password Manager")
window.config(padx=60, pady=60)
window.resizable(0, 0)
# setting canvas
canvas = Canvas(width=200, height=200)
logo_img = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=logo_img)
canvas.grid(row=0, column=1)

# Labels
website_label = Label(text="Website:")
website_label.grid(row=1, column=0)

email_label = Label(text="Email/Username:")
email_label.grid(row=2, column=0)

password_label = Label(text="Password:")
password_label.grid(row=3, column=0)

# Entries
website_entry = Entry(width=35)
website_entry.grid(row=1, column=1)
website_entry.focus()

email_entry = Entry(width=35)
email_entry.grid(row=2, column=1, columnspan=2)
email_entry.insert(END, "sachdevavaibhav.2001@gmail.com")

password_entry = Entry(width=35)
password_entry.grid(row=3, column=1)

# Buttons
gen_pass_button = Button(text="Generate Password", width=14, command=generate_password)
gen_pass_button.grid(row=3, column=3, padx=10)

check_pwned_pass_button = Button(text="Password Pwned?", command=pwned_main)
check_pwned_pass_button.grid(row=4, column=0, columnspan=2)

add_button = Button(text="Add", width=10, command=save)
add_button.grid(row=4, column=1, columnspan=3)

search_button = Button(text="Search", width=14, command=search)
search_button.grid(row=1, column=3, padx=10)

show_password_data = Button(text="Show Password Data", command=show_data_popup)
show_password_data.grid(row=5, column=1, pady=10)

window.mainloop()
