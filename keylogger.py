import tkinter as tk
from datetime import datetime

# File to store simulated logs
LOG_FILE = "keystroke_log.txt"

def log_key(event):
    key = event.char if event.char else f"[{event.keysym}]"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} - {key}\n")
    
    print(f"Captured: {key}")  # Visible output for testing

def start_test():
    window = tk.Tk()
    window.title("Keystroke Simulation (Security Research Tool)")
    
    label = tk.Label(window, text="Type inside this box to simulate keystroke capture:")
    label.pack(pady=10)
    
    text_box = tk.Text(window, height=5, width=40)
    text_box.pack()
    text_box.bind("<Key>", log_key)  # Only logs keys typed inside this box
    
    window.mainloop()

if __name__ == "__main__":
    print("Starting safe keystroke logging simulation...")
    start_test()
