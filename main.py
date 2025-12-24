import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import time
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from log_validator import is_valid_log
from log_reader import read_log_file


class SmartLogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Log Analyzer Dashboard")
        self.root.geometry("1000x700")
        self.root.configure(bg="#0c0c0c")

        self.log_file = None
        self.stop_flag = [True]
        self.valid_count = 0
        self.invalid_count = 0
        self.logs = []

        # Title
        tk.Label(
            root, text="🔍 Smart Log Analyzer", font=("Helvetica", 20, "bold"), fg="#00ff00", bg="#0c0c0c"
        ).pack(pady=10)

        # Buttons frame
        btn_frame = tk.Frame(root, bg="#0c0c0c")
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame, text="📂 Select Log File", command=self.select_log_file, bg="#1a1a1a",
            fg="#00ff00", font=("Helvetica", 12, "bold"), width=18
        ).grid(row=0, column=0, padx=10)

        tk.Button(
            btn_frame, text="▶ Start Analyzing", command=self.start_analyzing, bg="#1a1a1a",
            fg="#00ff00", font=("Helvetica", 12, "bold"), width=18
        ).grid(row=0, column=1, padx=10)

        tk.Button(
            btn_frame, text="⛔ Stop", command=self.stop_analyzing, bg="#1a1a1a",
            fg="#ff3333", font=("Helvetica", 12, "bold"), width=10
        ).grid(row=0, column=2, padx=10)

        # Log display area
        self.log_display = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, width=120, height=25, bg="#111111", fg="#00ff00",
            font=("Consolas", 10)
        )
        self.log_display.pack(pady=10)

        # Chart
        self.fig, self.ax = plt.subplots(figsize=(5, 3), facecolor="#0c0c0c")
        self.ax.set_facecolor("#111111")
        self.canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.canvas.get_tk_widget().pack(pady=10)

    # Select log file
    def select_log_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.log_file = file_path
            self.display_log(f"\n📁 Selected log file: {file_path}\n", "info")

    # Start analyzing logs
    def start_analyzing(self):
        if not self.log_file:
            messagebox.showwarning("No file selected", "Please select a log file first!")
            return
        if self.stop_flag[0] is False:
            self.display_log("⚠ Analyzer is already running...\n", "info")
            return

        self.stop_flag[0] = False
        self.display_log(f"🔍 Analyzing logs from: {self.log_file}\n", "info")
        threading.Thread(target=self.analyze_logs, daemon=True).start()
        self.display_log("🟢 Analyzer thread started successfully...\n", "info")

    # Stop analyzing logs
    def stop_analyzing(self):
        self.stop_flag[0] = True
        self.display_log("\n⛔ Stopped log analyzing.\n", "error")

    # Display log output
    def display_log(self, message, tag="info"):
        self.log_display.insert(tk.END, message)
        self.log_display.see(tk.END)
        self.root.update_idletasks()

    # Real-time log analysis
    def analyze_logs(self):
        self.valid_count = 0
        self.invalid_count = 0
        self.logs = []

        for line in read_log_file(self.log_file, self.stop_flag):
            if self.stop_flag[0]:
                break

            if is_valid_log(line):
                self.valid_count += 1
                self.display_log(f"✅ VALID LOG: {line}")
            else:
                self.invalid_count += 1
                self.display_log(f"❌ INVALID LOG: {line}")

            self.logs.append(line)
            self.update_chart()

    # Update matplotlib chart
    def update_chart(self):
        self.ax.clear()
        self.ax.bar(["Valid Logs", "Invalid Logs"], [self.valid_count, self.invalid_count],
                    color=["#00ff00", "#ff3333"])
        self.ax.set_title("Log Analysis Summary", color="#00ff00")
        self.ax.set_facecolor("#111111")
        self.fig.patch.set_facecolor("#0c0c0c")
        self.canvas.draw()


# Run app
if __name__ == "__main__":
    root = tk.Tk()
    app = SmartLogAnalyzerApp(root)
    root.mainloop()
