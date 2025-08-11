from yarwatch.config import icon_path
from PIL import Image
import customtkinter
import threading
from yarwatch.scanner import run_yara_pid, run_yara_file

scan_icon = customtkinter.CTkImage(Image.open(icon_path), size=(20, 20))


class CollapsibleScanFrame(customtkinter.CTkFrame):
    def __init__(self, master, header_text, body_lines, color="gray", result_dict=None, gui=None, **kwargs):
        super().__init__(
            master,
            fg_color=color,
            **kwargs
        )
        self.expanded = False
        self.body_lines = body_lines
        self.result_dict = result_dict or {}
        self.gui = gui

        # Header Frame with Button and Title
        self.header_frame = customtkinter.CTkFrame(self, fg_color=color)
        self.header_frame.pack(fill="x", padx=5, pady=(5, 0))

        self.toggle_button = customtkinter.CTkButton(
            self.header_frame,
            text="▶" + header_text,
            font=("Segoe UI", 16, "bold"),
            anchor="w",
            command=self.toggle,
            fg_color=color,
            hover_color="#333333",
            text_color="white",
            width=700
        )
        self.toggle_button.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.rescan_button = customtkinter.CTkButton(
            self.header_frame,
            text="Rescan",
            font=("Segoe UI", 14),
            fg_color="#0E2536",
            hover_color="#666666",
            command=self.rescan
        )
        self.rescan_button.pack(side="right", padx=5, pady=5)

        # Body with text box
        self.body_frame = customtkinter.CTkFrame(self, fg_color="#1e1e1e")
        self.body_text = customtkinter.CTkTextbox(
            self.body_frame,
            height=200,
            wrap="word",
            font=("Consolas", 16),
            text_color="white",
            fg_color="#1e1e1e"
        )
        self.body_text.pack(expand=True, fill="both", padx=5, pady=5)

        # Proper scroll bindings for just the text box
        self.body_text.bind("<Enter>", lambda e: self.body_text.bind("<MouseWheel>", self._on_textbox_scroll))
        self.body_text.bind("<Leave>", lambda e: self.body_text.unbind("<MouseWheel>"))

        self.body_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.body_frame.pack_forget()  # Start collapsed

        for line in self.body_lines:
            self.body_text.insert("end", line + "\n")

    def _on_textbox_scroll(self, event):
        self.body_text.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"

    def toggle(self):
        self.expanded = not self.expanded
        if self.expanded:
            self.body_frame.pack(fill="both", expand=True, padx=5, pady=5)
            self.toggle_button.configure(text="▼ " + self.toggle_button.cget("text")[2:])
        else:
            self.body_frame.pack_forget()
            self.toggle_button.configure(text="▶ " + self.toggle_button.cget("text")[2:])

    def rescan(self):
        target_type = self.result_dict.get("target_type")
        target = self.result_dict.get("target")

        if self.gui and target_type and target:
            if target_type == "file":
                self.gui.logger.log(f"[Rescan] Rescanning file: {target}")
                threading.Thread(target=run_yara_file, args=(target, self.gui, self.gui.feature_extractor, self.gui.logger)).start()
            elif target_type == "pid":
                self.gui.logger.log(f"[Rescan] Rescanning PID: {target}")
                threading.Thread(target=run_yara_pid, args=(int(target), self.gui, self.gui.feature_extractor, self.gui.logger), daemon=True).start()
