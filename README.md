# 🌊 Chill-guy Assistant

```
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣉⠟⣋⢻⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠇⠃⠐⠀⣼⣿⣿
⡿⠟⠛⠛⢉⣭⣥⣆⠀⢹⠁⠉⣽⣆⢿⣿⣿
⡇⠀⠀⠀⠈⣿⣿⣿⣶⣾⣷⣶⣿⣿⢸⣿⣿
⡇⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿
⣿⣦⣀⠠⠼⢿⢿⣿⡿⠛⣋⣬⣿⣿⣸⣿⣿
⣿⣿⣿⣿⣷⡶⢈⠛⠻⠶⠚⠛⠋⣡⡜⢿⣿
⣿⣿⣿⣿⣿⠇⢨⣿⣶⣶⣶⣾⣿⢀⡿⡌⣿
⣿⣿⣿⣿⣿⡆⠘⠿⣿⣿⣿⣿⠿⢠⣴⡇⣽
⣿⣿⣿⣿⣿⣿⡄⣦⠀⠀⠀⠀⣰⠌⠉⢸⣿
⣿⣿⣿⣿⣿⣿⣷⢹⠿⢧⠸⡿⣿⣷⡇⢸⣿
⣿⣿⣿⣿⣿⣿⣿⠈⣓⡛⡀⠓⠬⠽⠇⢸⣿
⣿⣿⣿⣿⣿⣿⢋⣥⠉⠉⣛⠘⠛⠛⢃⢸⣿
⣿⣿⣿⣿⣿⣿⣌⠒⠛⢈⡀⠜⠵⠄⠁⣼⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣾⣿⣿
```

**v0.4**
**Developed by Hyoka**

---

Chill-guy Assistant is your laid-back cyber buddy! 😎 This GUI-based Python app helps you check domain reputations using the VirusTotal API. Plus, it comes with a progress bar so you can chill while it works.

## 🚀 Features

- **📂 Upload CSV File**: Load a list of domains easily.
- **🔎 Domain Validation**: Only processes legit domains.
- **🛡️ VirusTotal Reputation Check**: Scans domains for potential threats.
- **📊 Progress Bar**: Watch the scan progress live.
- **💾 Auto-save Results**: Stores scan results in `scan_results_XXXXXXXXXX.csv`.

## 🔧 Requirements

Make sure you have:
- Python 3.x
- A VirusTotal API key (set as an environment variable `VT_API_KEY`)
- Required dependencies:
  ```sh
  pip install -r requirements.txt
  ```

## 🎮 How to Use

### 1. Set Up API Key
- Get your API key from [VirusTotal](https://www.virustotal.com/)
- Save it as an environment variable:
  - **Windows**:
    ```sh
    setx VT_API_KEY "your_api_key"
    ```
  - **Linux/macOS**:
    ```sh
    export VT_API_KEY="your_api_key"
    ```

### 2. Run the Program
```sh
python script.py
```

### 3. Upload a CSV File
- Make sure it has a `Remote Host` or `Address` column with domain names.
- Select the file using the GUI.

### 4. Start Scanning
- The app validates domains and checks their VirusTotal reputation.
- Progress bar keeps you in the loop.

### 5. View the Results
- Results are automatically saved in `scan_results_XXXXXXXXXX.csv`.


