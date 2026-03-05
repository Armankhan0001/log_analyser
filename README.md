# 🔍 Smart Log Analyzer (GUI – Real-Time)

## 📌 Overview

Smart Log Analyzer is a real-time GUI-based log monitoring tool built using Python and Tkinter.
It reads log files line-by-line, validates their format, and stops processing if an invalid log entry is detected.

This project is designed for cybersecurity learning and basic log monitoring practice on Linux (Kali/Ubuntu).

---

## 🚀 Features

* 📂 Select custom log file (.log / .txt)
* 🔎 Real-time log monitoring
* ✅ Detects valid logs
* ❌ Stops automatically on invalid log entries
* 🖥 Simple GUI dashboard
* 🧪 Includes sample log file for testing

---

## 🛠 Requirements

* Python 3.x
* Tkinter

Install Tkinter (if not installed):

```bash
sudo apt install python3-tk -y
```

---

## 📁 Project Structure

```
SmartLogAnalyzer/
│
├── main.py            # Main GUI application
├── log_reader.py      # Reads log file line by line
├── log_validator.py   # Validates log format
├── sample.log         # Sample log file for testing
└── README.md          # Project documentation
```

---

## ▶ How to Run

1. Extract the ZIP file:

   ```bash
   unzip SmartLogAnalyzer.zip
   cd SmartLogAnalyzer
   ```

2. Run the application:

   ```bash
   python3 main.py
   ```

3. In the GUI:

   * Click **Select Log File**
   * Choose `sample.log` (or your own log file)
   * Click **Start**
   * The analyzer will:

     * Process logs in real time
     * Stop automatically if an invalid log is detected

---

## 🧠 Log Format Rules

A log is considered **valid** if it:

* Starts with timestamp format:

  ```
  YYYY-MM-DD HH:MM:SS
  ```
* Contains a log level:

  * INFO
  * WARNING
  * ERROR
  * DEBUG

Example Valid Log:

```
2026-03-05 18:30:12 INFO User login successful
```

Example Invalid Log:

```
Login failed
Something wrong happened
```

---

## 🎯 Purpose

This project helps in:

* Understanding log validation
* Learning real-time monitoring concepts
* Practicing GUI development in Python
* Basic SOC-style log analysis simulation

---

## 🔐 Future Improvements (Optional)

* Add graphical statistics dashboard
* Detect brute-force login attempts
* Export results to CSV
* Add dark theme UI
* Monitor Linux system logs (/var/log)

---

## 👨‍💻 Author

Created for cybersecurity learning and log monitoring practice.

---

**Smart Log Analyzer – Real-Time Log Validation Tool**
