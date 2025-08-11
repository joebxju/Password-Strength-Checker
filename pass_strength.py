import tkinter as tk
from tkinter import ttk
import re
import math

def check_password_strength(password):
    """
    Analyzes the password strength based on length, complexity, and entropy.
    Returns a strength level and detailed feedback.
    """
    length = len(password)
    feedback = []
    score = 0
    
    # Character sets
    has_lower = re.search(r'[a-z]', password)
    has_upper = re.search(r'[A-Z]', password)
    has_digit = re.search(r'\d', password)
    # Using \W for non-alphanumeric characters + _
    has_special = re.search(r'[\W_]', password) 

    # --- 1. Score based on criteria ---
    
    # Score for length
    if length >= 8:
        score += 1
        feedback.append("✓ Length (≥8 characters)")
    else:
        feedback.append("✗ Length (<8 characters)")

    # Score for complexity (character types)
    char_types = sum([1 for check in [has_lower, has_upper, has_digit, has_special] if check])
    if char_types >= 3:
        score += char_types -1 # Bonus for multiple types
        feedback.append(f"✓ Complexity ({char_types}/4 character types)")
    else:
        feedback.append(f"✗ Complexity ({char_types}/4 character types)")

    # --- 2. Calculate Entropy ---
    
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += 32 # Common special characters

    if length > 0 and pool_size > 0:
        # Entropy formula: E = L * log2(R)
        entropy = length * math.log2(pool_size)
    else:
        entropy = 0
        
    feedback.append(f"🔐 Entropy: {entropy:.2f} bits")

    # --- 3. Determine Strength Level ---
    
    if entropy < 40 or length < 8:
        strength = "Very Weak"
        color = "red"
    elif entropy < 60:
        strength = "Weak"
        color = "orange"
    elif entropy < 80:
        strength = "Medium"
        color = "gold"
    elif entropy < 100:
        strength = "Strong"
        color = "limegreen"
    else:
        strength = "Very Strong"
        color = "green"

    # Don't show high strength for short passwords regardless of entropy
    if length < 8:
        strength = "Very Weak"
        color = "red"
        
    return strength, color, "\n".join(feedback)

def on_password_change(*args):
    """Callback function to update the UI when the password entry changes."""
    password = password_var.get()
    strength, color, feedback_text = check_password_strength(password)
    
    strength_label.config(text=f"Strength: {strength}", fg=color)
    feedback_label.config(text=feedback_text)
    
    # Update progress bar
    if strength == "Very Weak":
        progress_bar['value'] = 10
    elif strength == "Weak":
        progress_bar['value'] = 30
    elif strength == "Medium":
        progress_bar['value'] = 60
    elif strength == "Strong":
        progress_bar['value'] = 85
    else:
        progress_bar['value'] = 100

# --- GUI Setup ---
if __name__ == "__main__":
    # Main window
    root = tk.Tk()
    root.title("Password Strength Checker")
    root.geometry("400x300")
    root.resizable(False, False)

    # Style
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TProgressbar", thickness=20)

    # Main frame
    main_frame = tk.Frame(root, padx=20, pady=20)
    main_frame.pack(fill="both", expand=True)

    # Password entry
    tk.Label(main_frame, text="Enter Password:", font=("Helvetica", 12)).pack(anchor="w")
    password_var = tk.StringVar()
    password_var.trace_add("write", on_password_change)
    password_entry = tk.Entry(main_frame, textvariable=password_var, show="*", font=("Helvetica", 12), width=30)
    password_entry.pack(pady=5, fill="x")
    password_entry.focus()

    # Progress bar for strength visualization
    progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=300, mode="determinate")
    progress_bar.pack(pady=10)

    # Strength level label
    strength_label = tk.Label(main_frame, text="Strength: ", font=("Helvetica", 14, "bold"))
    strength_label.pack(pady=10)

    # Detailed feedback label
    feedback_label = tk.Label(main_frame, text="", font=("Helvetica", 10), justify="left")
    feedback_label.pack(anchor="w", pady=5)
    
    # Initialize the check for an empty password
    on_password_change()

    root.mainloop()