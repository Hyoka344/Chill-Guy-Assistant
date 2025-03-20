import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import os
import requests
import time
import re
from datetime import datetime
from PIL import Image, ImageTk

# Ambil API Key dari environment variable
API_KEY = os.getenv('VT_API_KEY')
if not API_KEY:
    messagebox.showerror("Error", "API Key tidak ditemukan. Harap set VT_API_KEY di environment variables.")
    exit()

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

    status = "Safe" if malicious == 0 and suspicious == 0 else "Potentially Harmful"

    return {
        'Country': attributes.get('country', 'Unknown'),
        'Owner': attributes.get('as_owner', 'Unknown'),
        'Malicious': malicious,
        'Suspicious': suspicious,
        'Total': sum(attributes.get('last_analysis_stats', {}).values()),
        'Scan Time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'Status': status
    }

# Fungsi untuk membaca file
def read_file(filepath):
    try:
        if not os.path.exists(filepath):
            messagebox.showerror("Error", "File tidak ditemukan.")
            return None

        df = pd.read_csv(filepath, on_bad_lines='skip', sep=None, engine='python')
        
        if df.empty:
            messagebox.showerror("Error", "File kosong atau tidak memiliki data yang valid.")
            return None

        messagebox.showinfo("File Loaded", "File berhasil dimuat!")
        return df
    except Exception as e:
        messagebox.showerror("Error", f"Kesalahan saat membaca file: {str(e)}")
        return None

# Fungsi untuk upload file
def upload_file():
    filepath = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not filepath:
        return

    df = read_file(filepath)
    if df is not None:
        process_data(df)

# Fungsi untuk memproses data
def process_data(df):
    results = []
    df['Address'] = df['Remote Host'].dropna().astype(str)
    domains = df['Address'].tolist()
    valid_domains = [d for d in domains if is_valid_domain(d)]
    
    total_domains = len(valid_domains)
    if total_domains == 0:
        messagebox.showwarning("Warning", "Tidak ada domain valid untuk diproses.")
        return
    
    progress_bar['maximum'] = total_domains
    
    for index, address in enumerate(valid_domains, start=1):
        vt_data = check_virustotal(address)
        if vt_data:
            results.append({
                'Address': address,
                'Country': vt_data['Country'],
                'Owner': vt_data['Owner'],
                'Malicious': vt_data['Malicious'],
                'Suspicious': vt_data['Suspicious'],
                'Total': vt_data['Total'],
                'Scan Time': vt_data['Scan Time'],
                'Status': vt_data['Status']
            })
        
        progress_bar['value'] = index
        progress_label.config(text=f"Scanning: {index}/{total_domains} domains")
        root.update_idletasks()
    
    if results:
        result_df = pd.DataFrame(results)
        result_df.to_csv("scan_results.csv", index=False)
        messagebox.showinfo("Scan Selesai", "Hasil scan tersimpan dalam 'scan_results.csv'")
    
# Buat GUI
root = tk.Tk()
root.title("Chill-guy assistant")
root.geometry("500x350")

# Load gambar
try:
    image = Image.open("chillguy.jpg")
    image = image.resize((100, 100))
    photo = ImageTk.PhotoImage(image)
    img_label = tk.Label(root, image=photo)
    img_label.pack(pady=10)
except Exception as e:
    messagebox.showwarning("Gambar Error", f"Tidak dapat memuat gambar: {str(e)}")

label = tk.Label(root, text="Chill-guy assistant", font=("Arial", 14))
label.pack(pady=10)

upload_button = tk.Button(root, text="Upload File (CSV saja)", command=upload_file)
upload_button.pack(pady=10)

progress_label = tk.Label(root, text="", font=("Arial", 10))
progress_label.pack(pady=5)

progress_bar = ttk.Progressbar(root, length=400, mode='determinate')
progress_bar.pack(pady=10)

root.mainloop()