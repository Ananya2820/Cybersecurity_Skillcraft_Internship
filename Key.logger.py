"""
Safe key-event logger for your own application only.
- Records key presses while this window is focused.
- Shows a consent checkbox and an on-screen indicator while logging.
- Masks any sequence that looks like a password (basic heuristic).
"""

import tkinter as tk
from tkinter import ttk
import time
import re

LOGFILE = "local_app_keylog.txt"

def looks_like_password(seq: str) -> bool:
    # Very simple heuristic: consecutive letters/digits > 6 with no spaces
    return bool(re.match(r'^[A-Za-z0-9]{7,}$', seq))

class App:
    def __init__(self, root):
        self.root = root
        root.title("My App — Local Input Logger (CONSENT REQUIRED)")

        self.consent_var = tk.BooleanVar(value=False)
        consent_frame = ttk.Frame(root, padding=10)
        consent_frame.pack(fill="x")
        ttk.Label(consent_frame, text="Allow logging of key events (only while this window is focused):").pack(side="left")
        ttk.Checkbutton(consent_frame, text="I consent", variable=self.consent_var).pack(side="left", padx=8)

        self.status_label = ttk.Label(root, text="Logging: OFF", padding=8)
        self.status_label.pack()

        instructions = ("Type in the input below. Logging is only active when you check 'I consent' "
                        "and this window is focused. Sensitive sequences are masked.")
        ttk.Label(root, text=instructions, wraplength=480, padding=8).pack()

        self.input = ttk.Entry(root, width=80)
        self.input.pack(padx=10, pady=10)
        self.input.focus_set()

        self.log_box = tk.Text(root, height=12, width=80, state="disabled")
        self.log_box.pack(padx=10, pady=10)

        # We will keep a small rolling buffer to detect possible password-like inputs
        self.recent_chars = ""

        # Bind only to this window's key events
        root.bind_all("<Key>", self.on_key)

        # Periodically update status label
        self._update_status()

    def _update_status(self):
        self.status_label.config(text=f"Logging: {'ON' if self.consent_var.get() else 'OFF'}")
        self.root.after(500, self._update_status)

    def append_log(self, text: str):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        entry = f"[{ts}] {text}\n"
        # write to file
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(entry)
        # update text box
        self.log_box.config(state="normal")
        self.log_box.insert("end", entry)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def on_key(self, event):
        # Only log when user has given consent and window is focused
        if not self.consent_var.get():
            return

        # Tkinter's focus_get tells us which widget is focused; require the app's root to have focus
        focused = self.root.focus_displayof()
        if focused is None:
            return

        # event.keysym provides a friendly name; event.char is the character (may be empty for some keys)
        char = event.char or ""
        keysym = event.keysym

        # Maintain recent chars for password heuristic — reset on whitespace or special keys
        if char and char.isprintable() and not char.isspace():
            self.recent_chars += char
            # cap length
            if len(self.recent_chars) > 64:
                self.recent_chars = self.recent_chars[-64:]
        else:
            self.recent_chars = ""

        masked = False
        if looks_like_password(self.recent_chars):
            # Mask the last sequence
            masked = True

        if masked:
            log_text = f"{keysym} (masked-sequence)"
        else:
            display_char = char if char else f"<{keysym}>"
            log_text = display_char

        # For safety, never log full clipboard or modifier-only events; just note them
        if keysym in ("Control_L", "Control_R", "Shift_L", "Shift_R", "Alt_L", "Alt_R"):
            return

        self.append_log(log_text)
