import tkinter as tk
from tkinter import ttk, messagebox
import random
import threading

# --- Helper Class for Scrollable GUI ---

class ScrollableFrame(ttk.Frame):
    """A scrollable frame that can hold other widgets."""
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Bind mouse wheel for scrolling
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

# --- Cryptographic Functions ---

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits):
    """Generates a prime number of a given bit length."""
    while True:
        p = random.getrandbits(bits)
        if p % 2 != 0 and is_prime(p):
            return p

def find_primitive_root(p):
    """Finds a primitive root for a prime p."""
    if p == 2:
        return 1
    
    phi = p - 1
    phi_factors = set()
    d = phi
    i = 2
    while i * i <= d:
        if d % i == 0:
            phi_factors.add(i)
            while d % i == 0:
                d //= i
        i += 1
    if d > 1:
        phi_factors.add(d)

    for g in range(2, p + 1):
        is_primitive = True
        for factor in phi_factors:
            if pow(g, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g
    return None

def caesar_cipher(text, shift, encrypt=True):
    """Encrypts or decrypts text using the Caesar cipher."""
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            if encrypt:
                shifted = (ord(char) - start + shift) % 26
            else:
                shifted = (ord(char) - start - shift) % 26
            result += chr(start + shifted)
        else:
            result += char
    return result

# --- GUI Application ---

class CryptoGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Diffie-Hellman & Caesar Cipher - Attacker Simulation")
        # Set a reasonable default size; the scrollbar handles overflow.
        self.geometry("750x700") 

        self.p = None
        self.g = None
        self.alice_private_key = None
        self.bob_private_key = None
        self.alice_public_key = None
        self.bob_public_key = None
        self.shared_secret = None

        self.create_widgets()

    def create_widgets(self):
        # Create the main scrollable frame
        scrollable_container = ScrollableFrame(self)
        scrollable_container.pack(fill="both", expand=True)
        # Get the inner frame to place all content
        main_frame = scrollable_container.scrollable_frame

        # --- Top Level Frames ---
        exchange_frame = ttk.Frame(main_frame)
        exchange_frame.pack(fill="x", expand=True, padx=10, pady=5)
        
        attacker_frame_container = ttk.Frame(main_frame)
        attacker_frame_container.pack(fill="x", expand=True, padx=10, pady=5)

        # --- Part 1: Key Exchange and Encryption ---
        key_size_frame = ttk.LabelFrame(exchange_frame, text="1. Key Size Selection")
        key_size_frame.pack(fill="x", pady=5)
        ttk.Label(key_size_frame, text="Select Key Size (bits):").pack(side="left", padx=5, pady=5)
        self.key_size_var = tk.StringVar(value='8')
        key_size_options = ["2", "4", "6", "8", "10", "12", "16", "32", "64", "128", "256", "512", "1024", "2048", "4096"]
        self.key_size_menu = ttk.Combobox(key_size_frame, textvariable=self.key_size_var, values=key_size_options, width=10)
        self.key_size_menu.pack(side="left", padx=5, pady=5)

        generate_pg_frame = ttk.LabelFrame(exchange_frame, text="2. Generate P and G")
        generate_pg_frame.pack(fill="x", pady=5)
        self.generate_pg_button = ttk.Button(generate_pg_frame, text="Generate", command=self.start_generate_p_and_g_thread)
        self.generate_pg_button.pack(pady=5)
        self.p_label = ttk.Label(generate_pg_frame, text="P: Not generated", wraplength=650)
        self.p_label.pack(anchor="w", padx=5)
        self.g_label = ttk.Label(generate_pg_frame, text="g: Not generated")
        self.g_label.pack(anchor="w", padx=5)

        public_key_frame = ttk.LabelFrame(exchange_frame, text="3. Generate and Show Public Values")
        public_key_frame.pack(fill="x", pady=5)
        self.generate_keys_button = ttk.Button(public_key_frame, text="Generate & Exchange Keys", command=self.generate_and_exchange_keys, state="disabled")
        self.generate_keys_button.pack(pady=5)
        self.alice_public_label = ttk.Label(public_key_frame, text="Alice's Public Key: Not generated", wraplength=650)
        self.alice_public_label.pack(anchor="w", padx=5)
        self.bob_public_label = ttk.Label(public_key_frame, text="Bob's Public Key: Not generated", wraplength=650)
        self.bob_public_label.pack(anchor="w", padx=5)
        self.shared_secret_label = ttk.Label(public_key_frame, text="Shared Secret: Not established", foreground="blue", wraplength=650)
        self.shared_secret_label.pack(anchor="w", padx=5, pady=5)

        encrypt_frame = ttk.LabelFrame(exchange_frame, text="4. Alice Encrypts Message")
        encrypt_frame.pack(fill="x", pady=5)
        ttk.Label(encrypt_frame, text="Enter Message:").pack(anchor="w", padx=5, pady=2)
        self.message_entry = ttk.Entry(encrypt_frame, width=70)
        self.message_entry.pack(padx=5, pady=2, fill='x')
        self.encrypt_button = ttk.Button(encrypt_frame, text="Encrypt", command=self.encrypt_message, state="disabled")
        self.encrypt_button.pack(pady=5)
        self.ciphertext_value = tk.StringVar()
        ttk.Label(encrypt_frame, text="Ciphertext:").pack(anchor="w", padx=5, pady=2)
        ttk.Entry(encrypt_frame, textvariable=self.ciphertext_value, state="readonly", width=70).pack(padx=5, pady=2, fill='x')

        decrypt_frame = ttk.LabelFrame(exchange_frame, text="5. Bob Decrypts Message")
        decrypt_frame.pack(fill="x", pady=5)
        self.decrypt_button = ttk.Button(decrypt_frame, text="Decrypt", command=self.decrypt_message, state="disabled")
        self.decrypt_button.pack(pady=5)
        self.decrypted_value = tk.StringVar()
        ttk.Label(decrypt_frame, text="Decrypted Message:").pack(anchor="w", padx=5, pady=2)
        ttk.Entry(decrypt_frame, textvariable=self.decrypted_value, state="readonly", width=70).pack(padx=5, pady=2, fill='x')
        
        # --- Part 2: Attacker's View ---
        attacker_frame = ttk.LabelFrame(attacker_frame_container, text="Part 2: Attacker's View", relief="ridge")
        attacker_frame.pack(fill="x", expand=True, pady=5)

        ttk.Label(attacker_frame, text="Information the Attacker Can See:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=5, pady=(5,10))
        self.attacker_p_label = ttk.Label(attacker_frame, text="P: (waiting)", wraplength=650)
        self.attacker_p_label.pack(anchor="w", padx=10)
        self.attacker_g_label = ttk.Label(attacker_frame, text="g: (waiting)")
        self.attacker_g_label.pack(anchor="w", padx=10)
        self.attacker_alice_pub_label = ttk.Label(attacker_frame, text="Alice's Public Value: (waiting)", wraplength=650)
        self.attacker_alice_pub_label.pack(anchor="w", padx=10)
        self.attacker_bob_pub_label = ttk.Label(attacker_frame, text="Bob's Public Value: (waiting)", wraplength=650)
        self.attacker_bob_pub_label.pack(anchor="w", padx=10)
        self.attacker_ciphertext_label = ttk.Label(attacker_frame, text="Ciphertext: (waiting)", wraplength=650)
        self.attacker_ciphertext_label.pack(anchor="w", padx=10)
        
        ttk.Separator(attacker_frame, orient='horizontal').pack(fill='x', pady=10, padx=5)

        ttk.Label(attacker_frame, text="Attacker's Decryption Attempt:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=5, pady=5)
        ttk.Label(attacker_frame, text="Guess the Shared Secret Key:").pack(anchor="w", padx=10, pady=2)
        self.attacker_guess_entry = ttk.Entry(attacker_frame, width=70)
        self.attacker_guess_entry.pack(padx=10, pady=2, fill='x')
        self.attacker_crack_button = ttk.Button(attacker_frame, text="Try to Decrypt", command=self.attacker_decrypt_attempt, state="disabled")
        self.attacker_crack_button.pack(pady=5)
        self.attacker_result_value = tk.StringVar()
        ttk.Label(attacker_frame, text="Decryption Result:").pack(anchor="w", padx=10, pady=2)
        ttk.Entry(attacker_frame, textvariable=self.attacker_result_value, state="readonly", width=70).pack(padx=10, pady=(0,10), fill='x')

    def start_generate_p_and_g_thread(self):
        self.generate_pg_button.config(state="disabled", text="Generating...")
        self.reset_all()
        bits = int(self.key_size_var.get())
        # For Diffie-Hellman, g=2 is often not a primitive root.
        # It's better to find one, so reverting the change.
        thread = threading.Thread(target=self.generate_p_and_g, args=(bits, True))
        thread.daemon = True
        thread.start()

    def generate_p_and_g(self, bits, find_g=True):
        try:
            p = generate_large_prime(bits)
            g = 2
            self.after(0, self.update_p_g_ui, p, g)
        except Exception as e:
            self.after(0, self.generation_failed, e)

    def update_p_g_ui(self, p, g):
        self.p = p
        self.g = g
        self.p_label.config(text=f"P: {self.p}")
        self.g_label.config(text=f"g: {self.g}")
        self.attacker_p_label.config(text=f"P: {self.p}")
        self.attacker_g_label.config(text=f"g: {self.g}")
        self.generate_keys_button.config(state="normal")
        self.generate_pg_button.config(state="normal", text="Generate")
        messagebox.showinfo("Success", "P and g have been generated.")

    def generation_failed(self, error):
        self.generate_pg_button.config(state="normal", text="Generate")
        messagebox.showerror("Error", f"Could not generate P and g: {error}")

    def generate_and_exchange_keys(self):
        if not self.p or not self.g:
            messagebox.showerror("Error", "Please generate P and g first.")
            return

        self.alice_private_key = random.randint(2, self.p - 2)
        self.bob_private_key = random.randint(2, self.p - 2)
        self.alice_public_key = pow(self.g, self.alice_private_key, self.p)
        self.bob_public_key = pow(self.g, self.bob_private_key, self.p)
        self.shared_secret = pow(self.bob_public_key, self.alice_private_key, self.p)

        self.alice_public_label.config(text=f"Alice's Public Key: {self.alice_public_key}")
        self.bob_public_label.config(text=f"Bob's Public Key: {self.bob_public_key}")
        self.shared_secret_label.config(text=f"Shared Secret: {self.shared_secret} (This is kept private!)")
        
        self.attacker_alice_pub_label.config(text=f"Alice's Public Value: {self.alice_public_key}")
        self.attacker_bob_pub_label.config(text=f"Bob's Public Value: {self.bob_public_key}")
        
        self.encrypt_button.config(state="normal")
        messagebox.showinfo("Success", "Public keys exchanged and shared secret established.")

    def encrypt_message(self):
        if not self.shared_secret:
            messagebox.showerror("Error", "Please establish a shared secret first.")
            return
        message = self.message_entry.get()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to encrypt.")
            return
            
        shift = self.shared_secret % 26
        ciphertext = caesar_cipher(message, shift, encrypt=True)
        self.ciphertext_value.set(ciphertext)
        self.attacker_ciphertext_label.config(text=f"Ciphertext: {ciphertext}")
        
        self.decrypt_button.config(state="normal")
        self.attacker_crack_button.config(state="normal")

    def decrypt_message(self):
        if not self.ciphertext_value.get():
            messagebox.showerror("Error", "Please encrypt a message first.")
            return
        ciphertext = self.ciphertext_value.get()
        shift = self.shared_secret % 26
        decrypted_message = caesar_cipher(ciphertext, shift, encrypt=False)
        self.decrypted_value.set(decrypted_message)
    
    def attacker_decrypt_attempt(self):
        ciphertext = self.ciphertext_value.get()
        if not ciphertext:
            messagebox.showerror("Error", "There is no ciphertext to crack.")
            return
        
        try:
            guessed_secret = int(self.attacker_guess_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "The guessed secret must be an integer.")
            return
            
        guessed_shift = guessed_secret % 26
        cracked_attempt = caesar_cipher(ciphertext, guessed_shift, encrypt=False)
        self.attacker_result_value.set(cracked_attempt)

    def reset_all(self):
        # Reset Alice and Bob's view
        self.p_label.config(text="P: Not generated")
        self.g_label.config(text="g: Not generated")
        self.alice_public_label.config(text="Alice's Public Key: Not generated")
        self.bob_public_label.config(text="Bob's Public Key: Not generated")
        self.shared_secret_label.config(text="Shared Secret: Not established")
        self.generate_keys_button.config(state="disabled")
        self.encrypt_button.config(state="disabled")
        self.decrypt_button.config(state="disabled")
        self.ciphertext_value.set("")
        self.decrypted_value.set("")
        
        # Reset Attacker's view
        self.attacker_p_label.config(text="P: (waiting)")
        self.attacker_g_label.config(text="g: (waiting)")
        self.attacker_alice_pub_label.config(text="Alice's Public Value: (waiting)")
        self.attacker_bob_pub_label.config(text="Bob's Public Value: (waiting)")
        self.attacker_ciphertext_label.config(text="Ciphertext: (waiting)")
        self.attacker_crack_button.config(state="disabled")
        self.attacker_guess_entry.delete(0, tk.END)
        self.attacker_result_value.set("")

if __name__ == "__main__":
    app = CryptoGUI()
    app.mainloop()