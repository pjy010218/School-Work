import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import threading
import math

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
        if is_prime(p):
            return p

def modular_inverse(a, m):
    """Calculates the modular multiplicative inverse of a modulo m."""
    return pow(a, -1, m)

# --- GUI Application ---

class RsaGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSA Cryptosystem & Attacker Simulation")
        self.geometry("800x900")

        # RSA parameters
        self.p, self.q, self.n, self.phi_n, self.e, self.d = (None,) * 6
        self.ciphertext = []

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)

        # --- Part 1: RSA Protocol ---
        protocol_frame = ttk.Frame(main_frame)
        protocol_frame.pack(fill="x", expand=True)

        key_gen_frame = ttk.LabelFrame(protocol_frame, text="1. Alice Generates RSA Keys")
        key_gen_frame.pack(fill="x", padx=5, pady=5)
        
        size_frame = ttk.Frame(key_gen_frame)
        size_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(size_frame, text="Select Modulus Key Size (bits for n):").pack(side="left", padx=5)
        self.key_size_var = tk.StringVar(value='128')
        key_size_options = ["16", "32", "64", "128", "256", "512", "1024"]
        self.key_size_menu = ttk.Combobox(size_frame, textvariable=self.key_size_var, values=key_size_options, width=10)
        self.key_size_menu.pack(side="left", padx=5)
        self.generate_keys_button = ttk.Button(size_frame, text="Generate Keys", command=self.start_generate_keys_thread)
        self.generate_keys_button.pack(side="left", padx=10)

        results_frame = ttk.Frame(key_gen_frame)
        results_frame.pack(fill='x', padx=5, pady=5)
        self.p_label = ttk.Label(results_frame, text="Prime p: (secret)", wraplength=750, foreground="red")
        self.p_label.pack(anchor="w", padx=5)
        self.q_label = ttk.Label(results_frame, text="Prime q: (secret)", wraplength=750, foreground="red")
        self.q_label.pack(anchor="w", padx=5)
        self.n_label = ttk.Label(results_frame, text="Modulus n (p*q):", wraplength=750)
        self.n_label.pack(anchor="w", padx=5)
        self.phi_label = ttk.Label(results_frame, text="Phi(n) (p-1)*(q-1): (secret)", wraplength=750, foreground="red")
        self.phi_label.pack(anchor="w", padx=5)
        self.e_label = ttk.Label(results_frame, text="Public Exponent (e):", wraplength=750)
        self.e_label.pack(anchor="w", padx=5)
        self.d_label = ttk.Label(results_frame, text="Private Exponent (d): (secret)", wraplength=750, foreground="red")
        self.d_label.pack(anchor="w", padx=5)
        
        encrypt_frame = ttk.LabelFrame(protocol_frame, text="2. Bob Encrypts a Message")
        encrypt_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(encrypt_frame, text="Bob uses Alice's Public Key (n, e) to encrypt.").pack(anchor='w', padx=5, pady=2)
        ttk.Label(encrypt_frame, text="Enter Message:").pack(anchor="w", padx=5)
        self.message_entry = ttk.Entry(encrypt_frame, width=90)
        self.message_entry.pack(padx=5, pady=2, fill='x')
        self.encrypt_button = ttk.Button(encrypt_frame, text="Encrypt", command=self.encrypt_message, state="disabled")
        self.encrypt_button.pack(pady=5)
        ttk.Label(encrypt_frame, text="Ciphertext (sent to Alice):").pack(anchor="w", padx=5)
        self.ciphertext_text = scrolledtext.ScrolledText(encrypt_frame, height=4, width=80, wrap=tk.WORD, state="disabled")
        self.ciphertext_text.pack(padx=5, pady=5, fill='x', expand=True)

        decrypt_frame = ttk.LabelFrame(protocol_frame, text="3. Alice Decrypts the Message")
        decrypt_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(decrypt_frame, text="Alice uses her Private Key (d) to decrypt.").pack(anchor='w', padx=5, pady=2)
        self.decrypt_button = ttk.Button(decrypt_frame, text="Decrypt", command=self.decrypt_message, state="disabled")
        self.decrypt_button.pack(pady=5)
        self.decrypted_value = tk.StringVar()
        ttk.Label(decrypt_frame, text="Decrypted Message:").pack(anchor="w", padx=5)
        ttk.Entry(decrypt_frame, textvariable=self.decrypted_value, state="readonly", width=90).pack(padx=5, pady=2, fill='x')

        # --- Part 2: Attacker's View ---
        attacker_frame = ttk.LabelFrame(main_frame, text="Attacker's View", relief="ridge")
        attacker_frame.pack(fill="x", expand=True, padx=5, pady=(15, 5))
        
        ttk.Label(attacker_frame, text="Information the Attacker Intercepts:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=5)
        self.attacker_n_label = ttk.Label(attacker_frame, text="Public Key n: (waiting)", wraplength=750)
        self.attacker_n_label.pack(anchor="w", padx=10)
        self.attacker_e_label = ttk.Label(attacker_frame, text="Public Key e: (waiting)", wraplength=750)
        self.attacker_e_label.pack(anchor="w", padx=10)
        self.attacker_ciphertext_label = ttk.Label(attacker_frame, text="Ciphertext: (waiting)")
        self.attacker_ciphertext_label.pack(anchor="w", padx=10, pady=(5,0))
        self.attacker_ciphertext_text = scrolledtext.ScrolledText(attacker_frame, height=4, width=80, wrap=tk.WORD, state="disabled")
        self.attacker_ciphertext_text.pack(padx=10, pady=(0,5), fill='x', expand=True)

        ttk.Separator(attacker_frame, orient='horizontal').pack(fill='x', pady=5, padx=5)
        ttk.Label(attacker_frame, text="Attack: Try to Factor n", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=5)
        
        guess_frame = ttk.Frame(attacker_frame)
        guess_frame.pack(fill='x', padx=10)
        ttk.Label(guess_frame, text="Guess p:").pack(side='left', padx=(0,5))
        self.attacker_p_guess = ttk.Entry(guess_frame)
        self.attacker_p_guess.pack(side='left', fill='x', expand=True)
        ttk.Label(guess_frame, text="Guess q:").pack(side='left', padx=(10,5))
        self.attacker_q_guess = ttk.Entry(guess_frame)
        self.attacker_q_guess.pack(side='left', fill='x', expand=True)

        self.crack_button = ttk.Button(attacker_frame, text="Attempt to Crack Key & Decrypt", command=self.attacker_crack_attempt, state="disabled")
        self.crack_button.pack(pady=5)
        self.attacker_result_value = tk.StringVar()
        ttk.Label(attacker_frame, text="Decryption Result:").pack(anchor="w", padx=10)
        ttk.Entry(attacker_frame, textvariable=self.attacker_result_value, state="readonly", width=90).pack(padx=10, pady=(2, 10), fill='x')

    def start_generate_keys_thread(self):
        self.generate_keys_button.config(state="disabled", text="Generating...")
        self.reset_all()
        try:
            bits = int(self.key_size_var.get())
            if bits < 16:
                raise ValueError("Key size must be at least 16 bits.")
            thread = threading.Thread(target=self.generate_rsa_keys, args=(bits,))
            thread.daemon = True
            thread.start()
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            self.generate_keys_button.config(state="normal", text="Generate Keys")

    def generate_rsa_keys(self, bits):
        try:
            prime_bits = bits // 2
            p = generate_large_prime(prime_bits)
            q = generate_large_prime(prime_bits)
            while p == q:
                q = generate_large_prime(prime_bits)

            n = p * q
            phi_n = (p - 1) * (q - 1)
            
            e = 65537
            if math.gcd(e, phi_n) != 1:
                # Find another e if 65537 is not suitable (rare for large primes)
                e = 3
                while math.gcd(e, phi_n) != 1:
                    e += 2

            d = modular_inverse(e, phi_n)
            
            self.after(0, self.update_rsa_ui, p, q, n, phi_n, e, d)
        except Exception as e:
            self.after(0, self.generation_failed, e)

    def update_rsa_ui(self, p, q, n, phi_n, e, d):
        self.p, self.q, self.n, self.phi_n, self.e, self.d = p, q, n, phi_n, e, d
        
        # Alice's View
        self.p_label.config(text=f"Prime p: {p} (secret)")
        self.q_label.config(text=f"Prime q: {q} (secret)")
        self.n_label.config(text=f"Modulus n (p*q): {n}")
        self.phi_label.config(text=f"Phi(n) (p-1)*(q-1): {phi_n} (secret)")
        self.e_label.config(text=f"Public Exponent (e): {e}")
        self.d_label.config(text=f"Private Exponent (d): {d} (secret)")
        
        # Attacker's View
        self.attacker_n_label.config(text=f"Public Key n: {n}")
        self.attacker_e_label.config(text=f"Public Key e: {e}")

        self.generate_keys_button.config(state="normal", text="Generate Keys")
        self.encrypt_button.config(state="normal")
        messagebox.showinfo("Success", "RSA keys have been generated.")

    def generation_failed(self, error):
        self.generate_keys_button.config(state="normal", text="Generate Keys")
        messagebox.showerror("Error", f"Could not generate keys: {error}")

    def encrypt_message(self):
        message = self.message_entry.get()
        if not self.n or not self.e:
            messagebox.showerror("Error", "Keys are not generated.")
            return
        if not message:
            messagebox.showwarning("Input Required", "Please enter a message to encrypt.")
            return
        
        self.ciphertext = [pow(ord(char), self.e, self.n) for char in message]
        
        cipher_str = str(self.ciphertext)
        for widget in [self.ciphertext_text, self.attacker_ciphertext_text]:
            widget.config(state="normal")
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, cipher_str)
            widget.config(state="disabled")

        self.attacker_ciphertext_label.config(text=f"Ciphertext: (see below)")
        self.decrypt_button.config(state="normal")
        self.crack_button.config(state="normal")

    def decrypt_message(self):
        if not self.ciphertext or not self.d:
            messagebox.showerror("Error", "No ciphertext to decrypt or private key is missing.")
            return
        
        decrypted_chars = [chr(pow(c, self.d, self.n)) for c in self.ciphertext]
        self.decrypted_value.set("".join(decrypted_chars))

    def attacker_crack_attempt(self):
        if not self.ciphertext:
            messagebox.showerror("Error", "There is no ciphertext to crack.")
            return
        try:
            p_guess = int(self.attacker_p_guess.get())
            q_guess = int(self.attacker_q_guess.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Guessed primes must be integers.")
            return

        if p_guess * q_guess != self.n:
            self.attacker_result_value.set("DECRYPTION FAILED: Guessed primes are incorrect.")
            messagebox.showerror("Failure", "The product of the guessed primes does not equal n.")
            return
            
        try:
            # If factorization is correct, the attacker can derive the private key
            phi_n_guess = (p_guess - 1) * (q_guess - 1)
            d_guess = modular_inverse(self.e, phi_n_guess)
            
            cracked_chars = [chr(pow(c, d_guess, self.n)) for c in self.ciphertext]
            self.attacker_result_value.set("".join(cracked_chars))
            messagebox.showinfo("Success!", "Attack successful! The factorization was correct and the message was decrypted.")
        except Exception as e:
            self.attacker_result_value.set(f"<DECRYPTION FAILED: {e}>")

    def reset_all(self):
        # Reset protocol view
        self.p_label.config(text="Prime p: (secret)")
        self.q_label.config(text="Prime q: (secret)")
        self.n_label.config(text="Modulus n (p*q):")
        self.phi_label.config(text="Phi(n) (p-1)*(q-1): (secret)")
        self.e_label.config(text="Public Exponent (e):")
        self.d_label.config(text="Private Exponent (d): (secret)")
        self.message_entry.delete(0, tk.END)
        self.decrypted_value.set("")
        for widget in [self.ciphertext_text, self.attacker_ciphertext_text]:
            widget.config(state="normal"); widget.delete(1.0, tk.END); widget.config(state="disabled")
        
        # Reset attacker view
        self.attacker_n_label.config(text="Public Key n: (waiting)")
        self.attacker_e_label.config(text="Public Key e: (waiting)")
        self.attacker_ciphertext_label.config(text="Ciphertext: (waiting)")
        self.attacker_p_guess.delete(0, tk.END)
        self.attacker_q_guess.delete(0, tk.END)
        self.attacker_result_value.set("")

        # Reset buttons
        self.encrypt_button.config(state="disabled")
        self.decrypt_button.config(state="disabled")
        self.crack_button.config(state="disabled")

if __name__ == "__main__":
    app = RsaGUI()
    app.mainloop()
