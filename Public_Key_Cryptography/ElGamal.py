import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import threading

# --- Cryptographic Functions ---

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_large_prime(bits):
    """Generates a prime number of a given bit length."""
    while True:
        p = random.getrandbits(bits)
        # Ensure the prime is large enough for the message (ord(char) < p)
        if p > 256 and is_prime(p):
            return p

def find_primitive_root(p):
    """Finds a primitive root for a prime p."""
    if p == 2: return 1
    phi = p - 1
    phi_factors = set()
    d = phi
    i = 2
    while i * i <= d:
        if d % i == 0:
            phi_factors.add(i)
            while d % i == 0: d //= i
        i += 1
    if d > 1: phi_factors.add(d)
    for g in range(2, p + 1):
        is_primitive = True
        for factor in phi_factors:
            if pow(g, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive: return g
    return None

# --- GUI Application ---

class ElGamalGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ElGamal Cryptosystem & Attacker Simulation")
        self.geometry("750x950") # Increased height for attacker panel

        # ElGamal parameters
        self.p = None
        self.g = None
        self.alice_private_key_d = None
        self.alice_public_key_e = None
        self.bob_ephemeral_key_k = []
        self.ciphertext = []

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)

        # --- Part 1: ElGamal Protocol ---
        protocol_frame = ttk.Frame(main_frame)
        protocol_frame.pack(fill="x", expand=True)

        key_size_frame = ttk.LabelFrame(protocol_frame, text="1. Choose Key Size")
        key_size_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(key_size_frame, text="Select Key Size (bits):").pack(side="left", padx=5, pady=5)
        self.key_size_var = tk.StringVar(value='10')
        key_size_options = ["8", "10", "12", "16", "32", "64", "128", "256", "512"]
        self.key_size_menu = ttk.Combobox(key_size_frame, textvariable=self.key_size_var, values=key_size_options, width=10)
        self.key_size_menu.pack(side="left", padx=5, pady=5)

        generate_pg_frame = ttk.LabelFrame(protocol_frame, text="2. Generate Global Parameters (g and P)")
        generate_pg_frame.pack(fill="x", padx=5, pady=5)
        self.generate_pg_button = ttk.Button(generate_pg_frame, text="Generate", command=self.start_generate_p_and_g_thread)
        self.generate_pg_button.pack(pady=5)
        self.p_label = ttk.Label(generate_pg_frame, text="P (Prime): Not generated", wraplength=700)
        self.p_label.pack(anchor="w", padx=5)
        self.g_label = ttk.Label(generate_pg_frame, text="g (Generator): Not generated")
        self.g_label.pack(anchor="w", padx=5)

        alice_key_frame = ttk.LabelFrame(protocol_frame, text="3. Alice Generates Her Keys")
        alice_key_frame.pack(fill="x", padx=5, pady=5)
        self.alice_gen_button = ttk.Button(alice_key_frame, text="Alice Generate Keys", command=self.alice_generate_keys, state="disabled")
        self.alice_gen_button.pack(pady=5)
        self.alice_private_label = ttk.Label(alice_key_frame, text="Alice's PRIVATE Key (d): Not generated", foreground="red", wraplength=700)
        self.alice_private_label.pack(anchor="w", padx=5)
        self.alice_public_label = ttk.Label(alice_key_frame, text="Alice's PUBLIC Key (e): Not generated", foreground="blue", wraplength=700)
        self.alice_public_label.pack(anchor="w", padx=5)
        self.full_pk_label = ttk.Label(alice_key_frame, text="--> Full Public Key Sent to Bob (P, g, e)", foreground="green")
        self.full_pk_label.pack(anchor="w", padx=5, pady=5)
        
        bob_encrypt_frame = ttk.LabelFrame(protocol_frame, text="4. Bob Encrypts and Sends a Message")
        bob_encrypt_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(bob_encrypt_frame, text="Enter Message to Encrypt:").pack(anchor="w", padx=5, pady=2)
        self.message_entry = ttk.Entry(bob_encrypt_frame, width=80)
        self.message_entry.pack(padx=5, pady=2)
        self.bob_encrypt_button = ttk.Button(bob_encrypt_frame, text="Bob Encrypts", command=self.bob_encrypt_message, state="disabled")
        self.bob_encrypt_button.pack(pady=5)
        ttk.Label(bob_encrypt_frame, text="--> Ciphertext (Y1, Y2) Sent to Alice:").pack(anchor="w", padx=5, pady=2)
        self.ciphertext_text = scrolledtext.ScrolledText(bob_encrypt_frame, height=4, width=80, wrap=tk.WORD, state="disabled")
        self.ciphertext_text.pack(padx=5, pady=5)

        alice_decrypt_frame = ttk.LabelFrame(protocol_frame, text="5. Alice Decrypts the Message")
        alice_decrypt_frame.pack(fill="x", padx=5, pady=5)
        self.alice_decrypt_button = ttk.Button(alice_decrypt_frame, text="Alice Decrypts", command=self.alice_decrypt_message, state="disabled")
        self.alice_decrypt_button.pack(pady=5)
        self.decrypted_value = tk.StringVar()
        ttk.Label(alice_decrypt_frame, text="Decrypted Message:").pack(anchor="w", padx=5, pady=2)
        ttk.Entry(alice_decrypt_frame, textvariable=self.decrypted_value, state="readonly", width=80).pack(padx=5, pady=2)

        # --- Part 2: Attacker's View ---
        attacker_frame = ttk.LabelFrame(main_frame, text="Part 2: Attacker's View", relief="ridge")
        attacker_frame.pack(fill="x", expand=True, padx=5, pady=(15, 5))

        ttk.Label(attacker_frame, text="Information the Attacker Intercepts:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=5, pady=5)
        self.attacker_info_frame = ttk.Frame(attacker_frame)
        self.attacker_info_frame.pack(fill='x', padx=10, pady=5)
        self.attacker_p_label = ttk.Label(self.attacker_info_frame, text="P: (waiting)", wraplength=700)
        self.attacker_p_label.pack(anchor="w")
        self.attacker_g_label = ttk.Label(self.attacker_info_frame, text="g: (waiting)")
        self.attacker_g_label.pack(anchor="w")
        self.attacker_e_label = ttk.Label(self.attacker_info_frame, text="Alice's Public Key (e): (waiting)", wraplength=700)
        self.attacker_e_label.pack(anchor="w")
        self.attacker_ciphertext_label = ttk.Label(self.attacker_info_frame, text="Ciphertext: (waiting)")
        self.attacker_ciphertext_label.pack(anchor="w", pady=(5,0))
        self.attacker_ciphertext_text = scrolledtext.ScrolledText(self.attacker_info_frame, height=4, width=80, wrap=tk.WORD, state="disabled")
        self.attacker_ciphertext_text.pack(pady=(0,5))
        
        ttk.Separator(attacker_frame, orient='horizontal').pack(fill='x', pady=5, padx=5)

        ttk.Label(attacker_frame, text="Attacker's Decryption Attempt:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=5, pady=5)
        ttk.Label(attacker_frame, text="Guess Alice's Private Key (d):").pack(anchor="w", padx=10)
        self.attacker_guess_entry = ttk.Entry(attacker_frame, width=80)
        self.attacker_guess_entry.pack(padx=10, pady=2)
        self.attacker_crack_button = ttk.Button(attacker_frame, text="Try to Decrypt with Guessed Key", command=self.attacker_decrypt_attempt, state="disabled")
        self.attacker_crack_button.pack(pady=5)
        self.attacker_result_value = tk.StringVar()
        ttk.Label(attacker_frame, text="Decryption Result:").pack(anchor="w", padx=10)
        ttk.Entry(attacker_frame, textvariable=self.attacker_result_value, state="readonly", width=80).pack(padx=10, pady=(2, 10))

    def start_generate_p_and_g_thread(self):
        self.generate_pg_button.config(state="disabled", text="Generating...")
        self.reset_all()
        bits = int(self.key_size_var.get())
        thread = threading.Thread(target=self.generate_p_and_g, args=(bits,))
        thread.daemon = True
        thread.start()

    def generate_p_and_g(self, bits):
        try:
            p = generate_large_prime(bits)
            g = find_primitive_root(p)
            self.after(0, self.update_p_g_ui, p, g)
        except Exception as e:
            self.after(0, self.generation_failed, e)

    def update_p_g_ui(self, p, g):
        self.p = p
        self.g = g
        self.p_label.config(text=f"P (Prime): {self.p}")
        self.g_label.config(text=f"g (Generator): {self.g}")
        self.attacker_p_label.config(text=f"P: {self.p}")
        self.attacker_g_label.config(text=f"g: {self.g}")
        self.alice_gen_button.config(state="normal")
        self.generate_pg_button.config(state="normal", text="Generate")
        messagebox.showinfo("Success", "Global parameters P and g have been generated.")

    def generation_failed(self, error):
        self.generate_pg_button.config(state="normal", text="Generate")
        messagebox.showerror("Error", f"Could not generate P and g: {error}")

    def alice_generate_keys(self):
        if not self.p or not self.g:
            messagebox.showerror("Error", "Generate P and g first.")
            return
        self.alice_private_key_d = random.randint(2, self.p - 2)
        self.alice_public_key_e = pow(self.g, self.alice_private_key_d, self.p)
        self.alice_private_label.config(text=f"Alice's PRIVATE Key (d): {self.alice_private_key_d}")
        self.alice_public_label.config(text=f"Alice's PUBLIC Key (e): {self.alice_public_key_e}")
        self.attacker_e_label.config(text=f"Alice's Public Key (e): {self.alice_public_key_e}")
        self.bob_encrypt_button.config(state="normal")
        messagebox.showinfo("Success", "Alice has generated her private and public keys.")

    def bob_encrypt_message(self):
        message = self.message_entry.get()
        if not all([self.p, self.g, self.alice_public_key_e]):
            messagebox.showerror("Error", "Key generation is not complete.")
            return
        if not message:
            messagebox.showwarning("Input Required", "Please enter a message to encrypt.")
            return
        self.ciphertext = []
        self.bob_ephemeral_key_k = []
        try:
            for char in message:
                m = ord(char)
                if m >= self.p:
                    raise ValueError(f"Message character '{char}' (value {m}) is too large for P={self.p}. Choose a larger key size.")
                k = random.randint(2, self.p - 2)
                self.bob_ephemeral_key_k.append(k)
                Y1 = pow(self.g, k, self.p)
                Y2 = (m * pow(self.alice_public_key_e, k, self.p)) % self.p
                self.ciphertext.append((Y1, Y2))
        except ValueError as e:
            messagebox.showerror("Encryption Error", str(e))
            self.ciphertext = []
            return
        
        cipher_str = str(self.ciphertext)
        for widget in [self.ciphertext_text, self.attacker_ciphertext_text]:
            widget.config(state="normal")
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, cipher_str)
            widget.config(state="disabled")
        self.alice_decrypt_button.config(state="normal")
        self.attacker_crack_button.config(state="normal")
        messagebox.showinfo("Success", "Bob has encrypted the message and sent the ciphertext.")

    def alice_decrypt_message(self):
        if not self.ciphertext:
            messagebox.showerror("Error", "There is no ciphertext to decrypt.")
            return
        try:
            decrypted_chars = []
            for Y1, Y2 in self.ciphertext:
                s = pow(Y1, self.alice_private_key_d, self.p)
                s_inv = pow(s, -1, self.p)
                m = (Y2 * s_inv) % self.p
                decrypted_chars.append(chr(m))
            decrypted_message = "".join(decrypted_chars)
            self.decrypted_value.set(decrypted_message)
            messagebox.showinfo("Success", "Alice has successfully decrypted the message.")
        except Exception as e:
            messagebox.showerror("Decryption Failed", f"An error occurred during decryption: {e}")

    def attacker_decrypt_attempt(self):
        if not self.ciphertext:
            messagebox.showerror("Error", "There is no ciphertext to crack.")
            return
        try:
            guessed_d = int(self.attacker_guess_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "The guessed private key 'd' must be an integer.")
            return
        try:
            cracked_chars = []
            for Y1, Y2 in self.ciphertext:
                s = pow(Y1, guessed_d, self.p)
                s_inv = pow(s, -1, self.p)
                m = (Y2 * s_inv) % self.p
                cracked_chars.append(chr(m))
            cracked_message = "".join(cracked_chars)
            self.attacker_result_value.set(cracked_message)
            if guessed_d == self.alice_private_key_d:
                messagebox.showinfo("Success!", "The attacker guessed the correct private key and decrypted the message!")
        except Exception as e:
            self.attacker_result_value.set(f"<DECRYPTION FAILED: {e}>")

    def reset_all(self):
        # Reset protocol view
        self.p_label.config(text="P (Prime): Not generated")
        self.g_label.config(text="g (Generator): Not generated")
        self.alice_private_label.config(text="Alice's PRIVATE Key (d): Not generated")
        self.alice_public_label.config(text="Alice's PUBLIC Key (e): Not generated")
        self.decrypted_value.set("")
        self.ciphertext_text.config(state="normal"); self.ciphertext_text.delete(1.0, tk.END); self.ciphertext_text.config(state="disabled")
        self.alice_gen_button.config(state="disabled"); self.bob_encrypt_button.config(state="disabled"); self.alice_decrypt_button.config(state="disabled")
        
        # Reset attacker's view
        self.attacker_p_label.config(text="P: (waiting)")
        self.attacker_g_label.config(text="g: (waiting)")
        self.attacker_e_label.config(text="Alice's Public Key (e): (waiting)")
        self.attacker_crack_button.config(state="disabled")
        self.attacker_guess_entry.delete(0, tk.END)
        self.attacker_result_value.set("")
        self.attacker_ciphertext_text.config(state="normal"); self.attacker_ciphertext_text.delete(1.0, tk.END); self.attacker_ciphertext_text.config(state="disabled")

if __name__ == "__main__":
    app = ElGamalGUI()
    app.mainloop()
