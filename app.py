import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from ai_client import AIClient
from security_tools import (
    get_defender_status,
    update_defender_signatures,
    run_quick_scan,
    run_full_scan,
    scan_path_with_defender,
    get_threat_history,
    hash_file,
    check_url_basic,
    get_security_summary,
)


# -----------------------------
# Sherlock AI Retro Theme
# -----------------------------
BLACK = "#050505"
DARK_BLACK = "#0B0B0B"
PANEL_BLACK = "#111111"
RED = "#FF1E1E"
DARK_RED = "#8B0000"
TEXT_RED = "#FF4D4D"
TEXT_GREY = "#B8B8B8"
WHITE = "#FFFFFF"


class SherlockAIApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.ai = AIClient()

        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / "sherlock_chat_log.txt"
        self.security_log_file = self.log_dir / "sherlock_security_log.txt"

        self.title("Sherlock AI // Local Security Assistant")
        self.geometry("1200x820")
        self.minsize(900, 650)
        self.configure(fg_color=BLACK)

        ctk.set_appearance_mode("dark")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.build_header()
        self.build_controls()
        self.build_security_panel()
        self.build_chat_area()
        self.build_input_panel()

    def build_header(self):
        self.header_frame = ctk.CTkFrame(
            self,
            fg_color=DARK_BLACK,
            border_color=RED,
            border_width=1,
            corner_radius=0
        )
        self.header_frame.grid(row=0, column=0, padx=18, pady=(18, 8), sticky="ew")
        self.header_frame.grid_columnconfigure(0, weight=1)

        self.header = ctk.CTkLabel(
            self.header_frame,
            text="SHERLOCK AI",
            font=("Consolas", 34, "bold"),
            text_color=RED
        )
        self.header.grid(row=0, column=0, padx=16, pady=(12, 0), sticky="w")

        self.sub_header = ctk.CTkLabel(
            self.header_frame,
            text="LOCAL AI ASSISTANT // DEFENDER SCAN CONTROL // LINK CHECKING // CYBERSECURITY UTILITIES",
            font=("Consolas", 12),
            text_color=TEXT_GREY
        )
        self.sub_header.grid(row=1, column=0, padx=16, pady=(0, 12), sticky="w")

    def build_controls(self):
        self.controls_frame = ctk.CTkFrame(
            self,
            fg_color=PANEL_BLACK,
            border_color=DARK_RED,
            border_width=1,
            corner_radius=0
        )
        self.controls_frame.grid(row=1, column=0, padx=18, pady=(0, 8), sticky="ew")
        self.controls_frame.grid_columnconfigure(6, weight=1)

        self.mode_label = ctk.CTkLabel(
            self.controls_frame,
            text="MODE:",
            font=("Consolas", 13, "bold"),
            text_color=TEXT_RED
        )
        self.mode_label.grid(row=0, column=0, padx=(14, 8), pady=10, sticky="w")

        self.mode_selector = ctk.CTkOptionMenu(
            self.controls_frame,
            values=[
                "General Chat",
                "Research Mode",
                "Cybersecurity Mode"
            ],
            fg_color=BLACK,
            button_color=DARK_RED,
            button_hover_color=RED,
            dropdown_fg_color=BLACK,
            dropdown_hover_color=DARK_RED,
            dropdown_text_color=TEXT_RED,
            text_color=TEXT_RED,
            font=("Consolas", 13),
            corner_radius=0
        )
        self.mode_selector.set("Cybersecurity Mode")
        self.mode_selector.grid(row=0, column=1, padx=(0, 14), pady=10, sticky="w")

        self.status_label = ctk.CTkLabel(
            self.controls_frame,
            text="STATUS: ONLINE",
            font=("Consolas", 13, "bold"),
            text_color=RED
        )
        self.status_label.grid(row=0, column=2, padx=(0, 14), pady=10, sticky="w")

        self.identity_label = ctk.CTkLabel(
            self.controls_frame,
            text="IDENTITY: SHERLOCK",
            font=("Consolas", 13),
            text_color=TEXT_GREY
        )
        self.identity_label.grid(row=0, column=3, padx=(0, 14), pady=10, sticky="w")

        self.warning_label = ctk.CTkLabel(
            self.controls_frame,
            text="NOTE: SECURITY TOOLS USE LOCAL DEFENDER / STATIC CHECKS",
            font=("Consolas", 12),
            text_color=TEXT_GREY
        )
        self.warning_label.grid(row=0, column=4, padx=(0, 14), pady=10, sticky="w")

    def build_security_panel(self):
        self.security_frame = ctk.CTkFrame(
            self,
            fg_color=PANEL_BLACK,
            border_color=DARK_RED,
            border_width=1,
            corner_radius=0
        )
        self.security_frame.grid(row=2, column=0, padx=18, pady=(0, 8), sticky="ew")

        for i in range(10):
            self.security_frame.grid_columnconfigure(i, weight=1)

        self.security_title = ctk.CTkLabel(
            self.security_frame,
            text="SECURITY CONTROL PANEL",
            font=("Consolas", 14, "bold"),
            text_color=RED
        )
        self.security_title.grid(row=0, column=0, columnspan=10, padx=12, pady=(10, 4), sticky="w")

        buttons = [
            ("DEFENDER\nSTATUS", self.handle_defender_status),
            ("UPDATE\nSIGNATURES", self.handle_update_signatures),
            ("QUICK\nSCAN", self.handle_quick_scan),
            ("FULL\nSCAN", self.handle_full_scan),
            ("SCAN\nFILE", self.handle_scan_file),
            ("SCAN\nFOLDER", self.handle_scan_folder),
            ("THREAT\nHISTORY", self.handle_threat_history),
            ("HASH\nFILE", self.handle_hash_file),
            ("SECURITY\nSUMMARY", self.handle_security_summary),
            ("CLEAR\nCHAT", self.clear_chat),
        ]

        for index, (text, command) in enumerate(buttons):
            button = self.make_security_button(text, command)
            button.grid(row=1, column=index, padx=6, pady=8, sticky="ew")

        self.url_entry = ctk.CTkEntry(
            self.security_frame,
            placeholder_text="Paste suspicious URL here, then press CHECK LINK",
            fg_color=BLACK,
            text_color=TEXT_RED,
            placeholder_text_color=TEXT_GREY,
            border_color=DARK_RED,
            border_width=1,
            font=("Consolas", 13),
            corner_radius=0
        )
        self.url_entry.grid(row=2, column=0, columnspan=8, padx=(8, 6), pady=(0, 12), sticky="ew")

        self.check_link_button = ctk.CTkButton(
            self.security_frame,
            text="CHECK LINK",
            fg_color=DARK_RED,
            hover_color=RED,
            text_color=WHITE,
            font=("Consolas", 13, "bold"),
            corner_radius=0,
            command=self.handle_check_link
        )
        self.check_link_button.grid(row=2, column=8, columnspan=2, padx=(6, 8), pady=(0, 12), sticky="ew")

    def build_chat_area(self):
        self.chat_box = ctk.CTkTextbox(
            self,
            wrap="word",
            font=("Consolas", 14),
            fg_color=BLACK,
            text_color=TEXT_RED,
            border_color=RED,
            border_width=1,
            corner_radius=0,
            scrollbar_button_color=DARK_RED,
            scrollbar_button_hover_color=RED
        )
        self.chat_box.grid(row=3, column=0, padx=18, pady=(0, 10), sticky="nsew")

        startup_text = (
            "╔══════════════════════════════════════════════════════════════════════╗\n"
            "║                         SHERLOCK AI INTERFACE                      ║\n"
            "╚══════════════════════════════════════════════════════════════════════╝\n\n"
            "[BOOT] Sherlock AI started.\n"
            "[MODE] Default mode: Cybersecurity Mode.\n"
            "[SECURITY] Microsoft Defender controls loaded.\n"
            "[LINK CHECK] Static URL analysis loaded.\n"
            "[INFO] Use the buttons above for scans and checks.\n"
            "[TIP] Type normally below to chat with Sherlock.\n"
            "[TIP] Use Ctrl + Enter to send quickly.\n\n"
        )

        self.chat_box.insert("end", startup_text)
        self.chat_box.configure(state="disabled")

    def build_input_panel(self):
        input_frame = ctk.CTkFrame(
            self,
            fg_color=PANEL_BLACK,
            border_color=DARK_RED,
            border_width=1,
            corner_radius=0
        )
        input_frame.grid(row=4, column=0, padx=18, pady=(0, 18), sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self.input_box = ctk.CTkTextbox(
            input_frame,
            height=90,
            wrap="word",
            font=("Consolas", 13),
            fg_color=BLACK,
            text_color=TEXT_RED,
            border_color=DARK_RED,
            border_width=1,
            corner_radius=0,
            scrollbar_button_color=DARK_RED,
            scrollbar_button_hover_color=RED
        )
        self.input_box.grid(row=0, column=0, padx=(12, 8), pady=12, sticky="ew")

        self.send_button = ctk.CTkButton(
            input_frame,
            text="SEND",
            width=110,
            fg_color=DARK_RED,
            hover_color=RED,
            text_color=WHITE,
            font=("Consolas", 13, "bold"),
            corner_radius=0,
            command=self.send_message
        )
        self.send_button.grid(row=0, column=1, padx=(0, 8), pady=12, sticky="ns")

        self.reset_button = ctk.CTkButton(
            input_frame,
            text="RESET AI",
            width=110,
            fg_color=BLACK,
            hover_color=DARK_RED,
            border_color=RED,
            border_width=1,
            text_color=TEXT_RED,
            font=("Consolas", 13, "bold"),
            corner_radius=0,
            command=self.reset_memory
        )
        self.reset_button.grid(row=0, column=2, padx=(0, 12), pady=12, sticky="ns")

        self.input_box.bind("<Control-Return>", lambda event: self.send_message())

    def make_security_button(self, text, command):
        return ctk.CTkButton(
            self.security_frame,
            text=text,
            fg_color=BLACK,
            hover_color=DARK_RED,
            border_color=RED,
            border_width=1,
            text_color=TEXT_RED,
            font=("Consolas", 11, "bold"),
            corner_radius=0,
            command=command
        )

    def append_chat(self, text: str):
        self.chat_box.configure(state="normal")
        self.chat_box.insert("end", text)
        self.chat_box.see("end")
        self.chat_box.configure(state="disabled")

    def clear_chat(self):
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", "end")
        self.chat_box.insert("end", "[SYSTEM] Chat display cleared.\n\n")
        self.chat_box.configure(state="disabled")

    def reset_memory(self):
        self.ai.reset()
        self.append_chat("[SYSTEM] Sherlock AI conversation memory reset.\n\n")
        self.save_to_log("System", "Sherlock AI conversation memory reset.")

    def save_to_log(self, speaker: str, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as file:
            file.write(f"[{timestamp}] {speaker}:\n{message}\n\n")

    def save_security_log(self, action: str, result: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.security_log_file, "a", encoding="utf-8") as file:
            file.write(f"[{timestamp}] {action}\n{result}\n\n")

    def set_busy(self, message="STATUS: WORKING"):
        self.status_label.configure(text=message, text_color=TEXT_RED)

    def set_online(self):
        self.status_label.configure(text="STATUS: ONLINE", text_color=RED)

    def send_message(self):
        user_message = self.input_box.get("1.0", "end").strip()

        if not user_message:
            return

        selected_mode = self.mode_selector.get()
        self.input_box.delete("1.0", "end")

        self.append_chat(f"> USER [{selected_mode}]\n{user_message}\n\n")
        self.save_to_log(f"User [{selected_mode}]", user_message)

        self.append_chat("[SHERLOCK] Processing query...\n\n")
        self.set_busy("STATUS: THINKING")
        self.send_button.configure(state="disabled", text="WAIT")

        thread = threading.Thread(
            target=self.get_ai_response,
            args=(user_message, selected_mode),
            daemon=True
        )
        thread.start()

    def get_ai_response(self, user_message: str, selected_mode: str):
        try:
            ai_response = self.ai.ask(user_message, selected_mode)
        except Exception as error:
            ai_response = f"An error occurred:\n\n{error}"

        self.after(0, self.show_ai_response, ai_response)

    def show_ai_response(self, ai_response: str):
        self.chat_box.configure(state="normal")

        current_text = self.chat_box.get("1.0", "end")
        current_text = current_text.replace("[SHERLOCK] Processing query...\n\n", "")

        self.chat_box.delete("1.0", "end")
        self.chat_box.insert("end", current_text)

        self.chat_box.insert("end", f"> SHERLOCK\n{ai_response}\n\n")
        self.chat_box.see("end")
        self.chat_box.configure(state="disabled")

        self.save_to_log("Sherlock", ai_response)

        self.set_online()
        self.send_button.configure(state="normal", text="SEND")

    def run_security_task(self, title: str, task_function, *args):
        self.append_chat(f"> SECURITY TASK\n{title}\n\n")
        self.append_chat("[SHERLOCK SECURITY] Running task...\n\n")
        self.set_busy("STATUS: SECURITY TASK")

        thread = threading.Thread(
            target=self._security_task_thread,
            args=(title, task_function, args),
            daemon=True
        )
        thread.start()

    def _security_task_thread(self, title: str, task_function, args):
        try:
            result = task_function(*args)
        except Exception as error:
            result = f"Security task failed:\n\n{error}"

        self.after(0, self.show_security_result, title, result)

    def show_security_result(self, title: str, result: str):
        self.chat_box.configure(state="normal")

        current_text = self.chat_box.get("1.0", "end")
        current_text = current_text.replace("[SHERLOCK SECURITY] Running task...\n\n", "")

        self.chat_box.delete("1.0", "end")
        self.chat_box.insert("end", current_text)

        self.chat_box.insert("end", f"> SHERLOCK SECURITY RESULT // {title}\n{result}\n\n")
        self.chat_box.see("end")
        self.chat_box.configure(state="disabled")

        self.save_security_log(title, result)
        self.set_online()

    def handle_defender_status(self):
        self.run_security_task("Microsoft Defender Status", get_defender_status)

    def handle_update_signatures(self):
        self.run_security_task("Update Defender Signatures", update_defender_signatures)

    def handle_quick_scan(self):
        self.run_security_task("Microsoft Defender Quick Scan", run_quick_scan)

    def handle_full_scan(self):
        self.run_security_task("Microsoft Defender Full Scan", run_full_scan)

    def handle_scan_file(self):
        selected_file = filedialog.askopenfilename(
            title="Select a file for Sherlock to scan",
            filetypes=[("All files", "*.*")]
        )

        if selected_file:
            self.run_security_task(
                f"Scan File: {selected_file}",
                scan_path_with_defender,
                selected_file
            )

    def handle_scan_folder(self):
        selected_folder = filedialog.askdirectory(
            title="Select a folder for Sherlock to scan"
        )

        if selected_folder:
            self.run_security_task(
                f"Scan Folder: {selected_folder}",
                scan_path_with_defender,
                selected_folder
            )

    def handle_threat_history(self):
        self.run_security_task("Microsoft Defender Threat History", get_threat_history)

    def handle_hash_file(self):
        selected_file = filedialog.askopenfilename(
            title="Select a file to hash",
            filetypes=[("All files", "*.*")]
        )

        if selected_file:
            self.run_security_task(
                f"Hash File: {selected_file}",
                hash_file,
                selected_file
            )

    def handle_check_link(self):
        url = self.url_entry.get().strip()

        if not url:
            self.append_chat("> SHERLOCK LINK CHECK\nNo URL entered.\n\n")
            return

        self.run_security_task(
            f"Static Link Check: {url}",
            check_url_basic,
            url
        )

    def handle_security_summary(self):
        self.run_security_task("Local Security Summary", get_security_summary)


if __name__ == "__main__":
    app = SherlockAIApp()
    app.mainloop()