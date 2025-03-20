import tkinter as tk
from tkinter import filedialog, ttk
import pandas as pd
import os
import requests
import time
import re
import threading
from datetime import datetime
from PIL import Image, ImageTk
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
API_KEY = os.getenv('VT_API_KEY')
if not API_KEY:
    exit("API Key tidak ditemukan. Harap set VT_API_KEY di file .env.")

# Validasi domain
def is_valid_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

# Cek reputasi alamat di VirusTotal
def check_virustotal(address):
    time.sleep(2)  # Hindari rate limiting
    url = f'https://www.virustotal.com/api/v3/domains/{address}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return None

    data = response.json()
    attributes = data.get('data', {}).get('attributes', {})

    malicious = attributes.get('last_analysis_stats', {}).get('malicious', 0)
    suspicious = attributes.get('last_analysis_stats', {}).get('suspicious', 0)

    return {
        'Country': attributes.get('country', 'Unknown'),
        'Owner': attributes.get('as_owner', 'Unknown'),
        'Malicious': malicious,
        'Suspicious': suspicious,
        'Total': sum(attributes.get('last_analysis_stats', {}).values()),
        'Scan Time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'Status': "Safe" if malicious == 0 and suspicious == 0 else "Potentially Harmful"
    }

# Fungsi untuk membaca file
def read_file(filepath):
    try:
        if not os.path.exists(filepath):
            return None

        if filepath.endswith(".csv"):
            df = pd.read_csv(filepath, on_bad_lines='skip', engine='python')
        elif filepath.endswith(".tsv"):
            df = pd.read_csv(filepath, on_bad_lines='skip', sep='\t', engine='python')
        else:
            return None

        return df if not df.empty else None
    except:
        return None

# Fungsi untuk upload file
def upload_file():
    filepath = filedialog.askopenfilename(filetypes=[("CSV & TSV Files", "*.csv;*.tsv")])
    if not filepath:
        return

    df = read_file(filepath)
    if df is not None:
        threading.Thread(target=process_data, args=(df,), daemon=True).start()

# Fungsi untuk memproses data
def process_data(df):
    results = []
    found_column = next((col for col in ["Remote Host", "Address"] if col in df.columns), None)
    
    if not found_column:
        return
    
    domains = [d for d in df[found_column].dropna().astype(str).tolist() if is_valid_domain(d)]
    total_domains = len(domains)
    if total_domains == 0:
        return
    
    progress_bar['maximum'] = total_domains
    progress_bar['value'] = 0
    progress_label.config(text="Scanning started...")
    progress_bar.pack()
    
    for index, address in enumerate(domains, start=1):
        vt_data = check_virustotal(address)
        if vt_data:
            results.append({
                'Address': address,
                **vt_data
            })
        
        progress_bar['value'] = index
        progress_label.config(text=f"Scanning: {index}/{total_domains} ({(index/total_domains)*100:.1f}%)")
        root.update_idletasks()
    
    if results:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.csv"
        pd.DataFrame(results).to_csv(filename, index=False)
        progress_label.config(text=f"Scan Completed! Results saved as {filename}")
    else:
        progress_label.config(text="Scan Completed! No results found.")

# Buat GUI
root = tk.Tk()
root.title("Chill-guy Assistant")
root.geometry("500x400")
root.configure(bg="#1A1B26")

main_frame = tk.Frame(root, bg="#24283B", padx=20, pady=20)
main_frame.pack(fill="both", expand=True)

# Load gambar
try:
    image = Image.open("Assets/chillguy.jpg").resize((100, 100))
    photo = ImageTk.PhotoImage(image)
    img_label = tk.Label(main_frame, image=photo, bg="#24283B")
    img_label.pack(pady=10)
except:
    pass

# Title label
title_label = tk.Label(main_frame, text="Chill-guy Assistant", font=("Arial", 16, "bold"), fg="#FFFFFF", bg="#24283B")
title_label.pack(pady=5)

# Upload Button
upload_button = tk.Button(main_frame, text="Upload CSV/TSV", font=("Arial", 12), command=upload_file, bg="#7AA2F7", fg="#FFFFFF")
upload_button.pack(pady=10)

# Progress Bar (Initially Hidden)
progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate")
progress_label = tk.Label(main_frame, text="", font=("Arial", 12), fg="#FFFFFF", bg="#24283B")
progress_label.pack()

# Footer
footer_label = tk.Label(root, text="developed by Hyoka344", font=("Arial", 10), fg="#FFFFFF", bg="#1A1B26")
footer_label.pack(side="bottom", pady=5)

root.mainloop()