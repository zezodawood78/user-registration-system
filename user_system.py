import tkinter as tk
from tkinter import messagebox
import hashlib
import os
import re
from datetime import datetime

# تشفير كلمة السر
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# حفظ الأحداث في ملف logs
def log_event(event):
    with open("log.txt", "a", encoding="utf-8") as file:
        file.write(f"{datetime.now()} - {event}\n")

# التحقق من قوة كلمة السر
def is_strong_password(password):
    return len(password) >= 8 and re.search(r'[A-Za-z]', password) and re.search(r'\d', password)

# التحقق من وجود المستخدم
def user_exists(username):
    if not os.path.exists("users.txt"):
        return False
    with open("users.txt", "r", encoding="utf-8") as file:
        for line in file:
            saved_username = line.strip().split(",")[0]
            if username == saved_username:
                return True
    return False

# تسجيل مستخدم جديد
def register_user():
    username = reg_username.get()
    password = reg_password.get()
    confirm = reg_confirm.get()

    if not username or not password:
        messagebox.showerror("خطأ", "كل الخانات مطلوبة.")
        return

    if user_exists(username):
        messagebox.showerror("خطأ", "اسم المستخدم موجود بالفعل.")
        return

    if password != confirm:
        messagebox.showerror("خطأ", "كلمتا السر غير متطابقتين.")
        return

    if not is_strong_password(password):
        messagebox.showwarning("كلمة السر ضعيفة", "كلمة السر لازم تكون 8 حروف على الأقل وتحتوي على أرقام وحروف.")
        return

    with open("users.txt", "a", encoding="utf-8") as file:
        file.write(f"{username},{hash_password(password)},user\n")

    log_event(f"تسجيل جديد: {username}")
    messagebox.showinfo("تم", "تم التسجيل بنجاح!")
    show_login()

# تسجيل الدخول
def login_user():
    username = login_username.get()
    password = login_password.get()
    hashed = hash_password(password)

    if not os.path.exists("users.txt"):
        messagebox.showerror("خطأ", "لا يوجد مستخدمون.")
        return

    with open("users.txt", "r", encoding="utf-8") as file:
        for line in file:
            u, p, role = line.strip().split(",")
            if username == u and hashed == p:
                log_event(f"تسجيل دخول: {username} ({role})")
                if role == "admin":
                    show_admin_dashboard(username)
                else:
                    show_user_dashboard(username)
                return

    messagebox.showerror("خطأ", "اسم المستخدم أو كلمة السر غير صحيحة.")

# حذف مستخدم
def delete_user(current_admin):
    username = del_username.get()

    if username == current_admin:
        messagebox.showerror("خطأ", "لا يمكنك حذف نفسك.")
        return

    if not user_exists(username):
        messagebox.showerror("خطأ", "المستخدم غير موجود.")
        return

    with open("users.txt", "r", encoding="utf-8") as file:
        lines = file.readlines()

    with open("users.txt", "w", encoding="utf-8") as file:
        for line in lines:
            u = line.strip().split(",")[0]
            if u != username:
                file.write(line)

    log_event(f"حذف مستخدم: {username} بواسطة {current_admin}")
    messagebox.showinfo("تم", f"تم حذف المستخدم {username}")
    del_username.delete(0, tk.END)

# تغيير نوع مستخدم
def change_user_role():
    username = role_username.get()
    if not user_exists(username):
        messagebox.showerror("خطأ", "المستخدم غير موجود.")
        return

    lines = []
    with open("users.txt", "r", encoding="utf-8") as file:
        for line in file:
            u, p, r = line.strip().split(",")
            if u == username:
                new_role = "admin" if r == "user" else "user"
                lines.append(f"{u},{p},{new_role}\n")
                log_event(f"تغيير صلاحية: {username} إلى {new_role}")
            else:
                lines.append(line)

    with open("users.txt", "w", encoding="utf-8") as file:
        file.writelines(lines)

    messagebox.showinfo("تم", f"تم تغيير نوع المستخدم {username}")
    role_username.delete(0, tk.END)

# عرض كل المستخدمين
def show_all_users():
    if not os.path.exists("users.txt"):
        messagebox.showinfo("المستخدمين", "لا يوجد مستخدمون.")
        return

    users_text = ""
    with open("users.txt", "r", encoding="utf-8") as file:
        for line in file:
            u, _, r = line.strip().split(",")
            users_text += f"{u} ({r})\n"

    messagebox.showinfo("قائمة المستخدمين", users_text)

# ---------------- الواجهات ----------------

def show_login():
    clear_window()
    tk.Label(root, text="تسجيل الدخول", bg="#4267B2", fg="white", font=("Arial", 18, "bold")).pack(pady=40)
    tk.Label(root, text="اسم المستخدم", font=("Arial", 14)).pack(pady=10)
    global login_username
    login_username = tk.Entry(root, font=("Arial", 12), bd=2, relief="solid")
    login_username.pack(pady=10, ipady=5, ipadx=10)

    tk.Label(root, text="كلمة السر", font=("Arial", 14)).pack(pady=10)
    global login_password
    login_password = tk.Entry(root, show="*", font=("Arial", 12), bd=2, relief="solid")
    login_password.pack(pady=10, ipady=5, ipadx=10)

    tk.Button(root, text="دخول", bg="#34b7f1", fg="white", font=("Arial", 14, "bold"), command=login_user, width=20).pack(pady=15)
    tk.Button(root, text="ليس لديك حساب؟ سجل الآن", bg="#f4f4f4", fg="black", font=("Arial", 12), command=show_register).pack(pady=10)

def show_register():
    clear_window()
    tk.Label(root, text="تسجيل مستخدم جديد", bg="#4267B2", fg="white", font=("Arial", 18, "bold")).pack(pady=40)

    tk.Label(root, text="اسم المستخدم", font=("Arial", 14)).pack(pady=10)
    global reg_username
    reg_username = tk.Entry(root, font=("Arial", 12), bd=2, relief="solid")
    reg_username.pack(pady=10, ipady=5, ipadx=10)

    tk.Label(root, text="كلمة السر", font=("Arial", 14)).pack(pady=10)
    global reg_password
    reg_password = tk.Entry(root, show="*", font=("Arial", 12), bd=2, relief="solid")
    reg_password.pack(pady=10, ipady=5, ipadx=10)

    tk.Label(root, text="تأكيد كلمة السر", font=("Arial", 14)).pack(pady=10)
    global reg_confirm
    reg_confirm = tk.Entry(root, show="*", font=("Arial", 12), bd=2, relief="solid")
    reg_confirm.pack(pady=10, ipady=5, ipadx=10)

    tk.Button(root, text="تسجيل", bg="#34b7f1", fg="white", font=("Arial", 14, "bold"), command=register_user, width=20).pack(pady=15)
    tk.Button(root, text="رجوع", bg="#f4f4f4", fg="black", font=("Arial", 12), command=show_login).pack(pady=10)

def show_user_dashboard(username):
    clear_window()
    tk.Label(root, text=f"مرحبًا {username}", font=("Arial", 18, "bold"), fg="#34b7f1").pack(pady=40)
    tk.Label(root, text="أنت مستخدم عادي.", font=("Arial", 14)).pack(pady=10)
    tk.Button(root, text="خروج", bg="#f44336", fg="white", font=("Arial", 14, "bold"), command=show_login, width=20).pack(pady=15)

def show_admin_dashboard(username):
    clear_window()
    tk.Label(root, text=f"مرحبًا {username} (أدمن)", font=("Arial", 18, "bold"), fg="#34b7f1").pack(pady=40)

    tk.Button(root, text="عرض كل المستخدمين", bg="#34b7f1", fg="white", font=("Arial", 14, "bold"), command=show_all_users, width=20).pack(pady=15)
    tk.Label(root, text="حذف مستخدم", font=("Arial", 14)).pack(pady=10)
    global del_username
    del_username = tk.Entry(root, font=("Arial", 12), bd=2, relief="solid")
    del_username.pack(pady=10, ipady=5, ipadx=10)
    tk.Button(root, text="حذف", bg="#e76f51", fg="white", font=("Arial", 12, "bold"), command=lambda: delete_user(username), width=20).pack(pady=10)

    tk.Label(root, text="تغيير صلاحية مستخدم", font=("Arial", 14)).pack(pady=10)
    global role_username
    role_username = tk.Entry(root, font=("Arial", 12), bd=2, relief="solid")
    role_username.pack(pady=10, ipady=5, ipadx=10)
    tk.Button(root, text="تغيير", bg="#f4a261", fg="black", font=("Arial", 12, "bold"), command=change_user_role, width=20).pack(pady=10)

    tk.Button(root, text="خروج", bg="#f44336", fg="white", font=("Arial", 14, "bold"), command=show_login, width=20).pack(pady=20)

def clear_window():
    for widget in root.winfo_children():
        widget.destroy()

# ---------------- تشغيل ----------------
root = tk.Tk()
root.title("نظام تسجيل المستخدمين")
root.geometry("500x700")
root.configure(bg="#f4f4f4")
show_login()
root.mainloop()