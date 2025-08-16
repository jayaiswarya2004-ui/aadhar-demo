import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import re, json, random, os, hashlib
import numpy as np

# ====== Crypto helpers (toy lattice demo) ======
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, q):
    g, x, _ = egcd(a % q, q)
    if g != 1:
        raise ValueError("No modular inverse (not coprime)")
    return x % q

def mod_matrix_inverse(S, q):
    n = S.shape[0]
    A = np.concatenate((S % q, np.eye(n, dtype=int)), axis=1)
    for i in range(n):
        if A[i, i] % q == 0:
            for k in range(i+1, n):
                if A[k, i] % q != 0:
                    A[[i, k]] = A[[k, i]]
                    break
        inv = modinv(int(A[i, i]) % q, q)
        A[i] = (A[i] * inv) % q
        for j in range(n):
            if i != j:
                factor = A[j, i] % q
                if factor != 0:
                    A[j] = (A[j] - factor * A[i]) % q
    return A[:, n:] % q

def digital_signature(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def generate_secret_key(n, q):
    while True:
        S = np.random.randint(1, q, size=(n, n))
        try:
            if int(round(np.linalg.det(S))) % q != 0:
                _ = mod_matrix_inverse(S, q)
                return S % q
        except Exception:
            pass

def generate_error_matrix(shape, emax=2):
    return np.random.randint(0, emax+1, size=shape)

def aadhaar_to_matrix(aadhaar: str):
    digits = list(map(int, aadhaar))
    while len(digits) % 3 != 0:
        digits.append(0)
    return np.array(digits, dtype=int).reshape(-1, 3)

def encrypt_aadhaar(aadhaar: str, S: np.ndarray, q: int, emax: int):
    A = aadhaar_to_matrix(aadhaar)
    E = generate_error_matrix(A.shape, emax)
    B = (A.dot(S) + E) % q
    sig = digital_signature(str(B))
    return {"A": A.tolist(), "E": E.tolist(), "B": B.tolist(), "signature": sig}

def decrypt_aadhaar(B, E, S, q):
    B = np.array(B, dtype=int)
    E = np.array(E, dtype=int)
    Sinv = mod_matrix_inverse(np.array(S, dtype=int), q)
    Arec = ((B - E) % q).dot(Sinv) % q
    return Arec.astype(int)

def random_aadhaar():
    first = str(random.randint(2, 9))
    rest = ''.join(str(random.randint(0, 9)) for _ in range(11))
    return first + rest

# ====== Tkinter App ======
class LoginFrame(ttk.Frame):
    def __init__(self, master, on_success):
        super().__init__(master, padding=16)
        self.on_success = on_success

        ttk.Label(self, text="Login", font=("Segoe UI", 18, "bold")).grid(row=0, column=0, columnspan=2, pady=(0,12))

        ttk.Label(self, text="Email").grid(row=1, column=0, sticky="w", padx=(0,8))
        ttk.Label(self, text="Password").grid(row=2, column=0, sticky="w", padx=(0,8))

        self.var_email = tk.StringVar()
        self.var_pass  = tk.StringVar()

        ttk.Entry(self, textvariable=self.var_email, width=32).grid(row=1, column=1, sticky="we")
        ttk.Entry(self, textvariable=self.var_pass,  width=32, show="•").grid(row=2, column=1, sticky="we", pady=(4,8))

        ttk.Button(self, text="Login", command=self.try_login).grid(row=3, column=0, columnspan=2, pady=6)
        self.columnconfigure(1, weight=1)

        ttk.Label(self, text="(Demo only – local validation, no real server)").grid(row=4, column=0, columnspan=2, pady=(8,0))

    def try_login(self):
        email = self.var_email.get().strip()
        pwd   = self.var_pass.get().strip()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            messagebox.showerror("Invalid email", "Please enter a valid email.")
            return
        if len(pwd) < 4:
            messagebox.showerror("Weak password", "Use at least 4 characters (demo).")
            return
        self.on_success(email)

class MainFrame(ttk.Frame):
    def __init__(self, master, user_email):
        super().__init__(master, padding=12)
        self.user_email = user_email

        # crypto settings
        self.q = tk.IntVar(value=97)
        self.emax = tk.IntVar(value=2)
        self.S = generate_secret_key(3, self.q.get())
        self.last = None
        self.cur_aadhaar = tk.StringVar()

        # header
        head = ttk.Frame(self); head.pack(fill="x")
        ttk.Label(head, text="Post-Quantum Aadhaar Demo", font=("Segoe UI", 16, "bold")).pack(side="left")
        ttk.Label(head, text=f"  |  signed in as {user_email}", foreground="#555").pack(side="left", padx=8)
        ttk.Button(head, text="New Secret Key", command=self.new_key).pack(side="right")

        # form
        form = ttk.LabelFrame(self, text="User details"); form.pack(fill="x", pady=8)
        self.v_name = tk.StringVar(); self.v_age = tk.StringVar(); self.v_gender = tk.StringVar(value="Female"); self.v_addr = tk.StringVar()

        ttk.Label(form, text="Name").grid(row=0,column=0,sticky="w");  ttk.Entry(form, textvariable=self.v_name, width=28).grid(row=0,column=1,sticky="w", padx=6, pady=4)
        ttk.Label(form, text="Age").grid(row=0,column=2,sticky="w");   ttk.Entry(form, textvariable=self.v_age, width=6).grid(row=0,column=3,sticky="w", padx=6)
        ttk.Label(form, text="Gender").grid(row=1,column=0,sticky="w");ttk.Combobox(form, textvariable=self.v_gender, values=["Female","Male","Other"], width=12, state="readonly").grid(row=1,column=1,sticky="w", padx=6)
        ttk.Label(form, text="Address").grid(row=1,column=2,sticky="w");ttk.Entry(form, textvariable=self.v_addr, width=36).grid(row=1,column=3,sticky="we", padx=6)

        ttk.Button(form, text="Generate Aadhaar", command=self.gen_aadhaar).grid(row=0,column=4,rowspan=2,padx=10)
        self.lbl_aad = ttk.Label(form, text="Generated Aadhaar: —", font=("Consolas", 12, "bold"))
        self.lbl_aad.grid(row=2, column=0, columnspan=5, sticky="w", pady=(6,4))

        # action bar
        bar = ttk.Frame(self); bar.pack(fill="x", pady=4)
        ttk.Button(bar, text="Encrypt", command=self.do_encrypt).pack(side="left", padx=4)
        ttk.Button(bar, text="Decrypt", command=self.do_decrypt).pack(side="left", padx=4)
        ttk.Button(bar, text="Verify Signature", command=self.do_verify).pack(side="left", padx=4)
        ttk.Button(bar, text="Save JSON", command=self.save_json).pack(side="right")
        ttk.Button(bar, text="Load JSON", command=self.load_json).pack(side="right", padx=6)

        # panes
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL); paned.pack(fill="both", expand=True, pady=6)
        lf = ttk.Labelframe(paned, text="Ciphertext & Signature"); rf = ttk.Labelframe(paned, text="Decryption & Status")
        paned.add(lf, weight=1); paned.add(rf, weight=1)

        self.out_cipher = tk.Text(lf, height=16); self.out_cipher.pack(fill="both", expand=True, padx=6, pady=6); self.out_cipher.configure(font=("Consolas",11))
        self.out_plain  = tk.Text(rf, height=16); self.out_plain.pack(fill="both", expand=True, padx=6, pady=6);  self.out_plain.configure(font=("Consolas",11))

        self.status = tk.StringVar(value="Ready"); ttk.Label(self, textvariable=self.status, relief=tk.SUNKEN, anchor="w").pack(fill="x", pady=(4,0))

    # actions
    def new_key(self):
        self.S = generate_secret_key(3, self.q.get())
        messagebox.showinfo("Secret key", "New secret key S generated.")

    def gen_aadhaar(self):
        if not self.v_name.get().strip():
            messagebox.showwarning("Name?", "Enter a name.")
            return
        a = random_aadhaar()
        self.cur_aadhaar.set(a)
        self.lbl_aad.configure(text=f"Generated Aadhaar: {a[0:4]} {a[4:8]} {a[8:12]}")
        self.status.set("Aadhaar generated.")

    def do_encrypt(self):
        a = self.cur_aadhaar.get().strip()
        if not (a.isdigit() and len(a)==12):
            messagebox.showerror("Invalid Aadhaar", "Generate Aadhaar first.")
            return
        self.last = encrypt_aadhaar(a, self.S, self.q.get(), self.emax.get())
        self.render_cipher(self.last)
        self.status.set("Encrypted.")

    def do_decrypt(self):
        if not self.last:
            messagebox.showwarning("No data", "Encrypt first.")
            return
        Arec = decrypt_aadhaar(self.last["B"], self.last["E"], self.S, self.q.get())
        self.render_plain(Arec)
        self.status.set("Decrypted.")

    def do_verify(self):
        if not self.last:
            messagebox.showwarning("No data", "Encrypt first.")
            return
        sig_now = digital_signature(str(np.array(self.last["B"])))
        ok = (sig_now == self.last["signature"])
        self.status.set("✅ Signature OK" if ok else "❌ Signature mismatch")

    def save_json(self):
        if not self.last:
            messagebox.showwarning("Nothing to save", "Encrypt first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
        if not path: return
        payload = {
            "user": {
                "email": self.user_email,
                "name": self.v_name.get(), "age": self.v_age.get(),
                "gender": self.v_gender.get(), "address": self.v_addr.get(),
                "aadhaar": self.cur_aadhaar.get()
            },
            "crypto": {
                "q": self.q.get(), "emax": self.emax.get(),
                "S": self.S.tolist(), "record": self.last
            }
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        self.status.set(f"Saved: {os.path.basename(path)}")

    def load_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            u = payload.get("user", {}); c = payload.get("crypto", {})
            self.v_name.set(u.get("name","")); self.v_age.set(u.get("age",""))
            self.v_gender.set(u.get("gender","Female")); self.v_addr.set(u.get("address",""))
            aad = u.get("aadhaar",""); self.cur_aadhaar.set(aad)
            self.lbl_aad.configure(text=f"Generated Aadhaar: {aad[0:4]} {aad[4:8]} {aad[8:12]}" if len(aad)==12 else "Generated Aadhaar: —")
            self.q.set(int(c.get("q",97))); self.emax.set(int(c.get("emax",2)))
            self.S = np.array(c.get("S"), dtype=int); self.last = c.get("record")
            self.render_cipher(self.last); self.status.set(f"Loaded: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Load error", str(e))

    # render helpers
    def render_cipher(self, record):
        self.out_cipher.delete("1.0", tk.END)
        if not record: return
        B = np.array(record["B"]); E = np.array(record["E"]); A = np.array(record["A"]); sig = record["signature"]
        self.out_cipher.insert(tk.END, "Encrypted matrix B (ciphertext):\n")
        self.out_cipher.insert(tk.END, f"{B}\n\nError matrix E:\n{E}\n\nOriginal A (for reference):\n{A}\n\nSignature (SHA-256 of B):\n{sig}\n")

    def render_plain(self, Arec):
        self.out_plain.delete("1.0", tk.END)
        self.out_plain.insert(tk.END, "Decrypted matrix A (recovered):\n")
        self.out_plain.insert(tk.END, f"{Arec}\n\n")
        digits = ''.join(str(int(x)) for x in Arec.flatten())
        self.out_plain.insert(tk.END, "Recovered Aadhaar (first 12 digits):\n")
        self.out_plain.insert(tk.END, f"{digits[:12]}\n")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PQ Aadhaar Demo (Prototype)")
        self.geometry("1000x700")
        self.resizable(True, True)
        self.show_login()

    def show_login(self):
        for w in self.winfo_children(): w.destroy()
        LoginFrame(self, self.on_login_success).pack(fill="both", expand=True)

    def on_login_success(self, email):
        for w in self.winfo_children(): w.destroy()
        MainFrame(self, email).pack(fill="both", expand=True)

if __name__ == "__main__":
    App().mainloop()
