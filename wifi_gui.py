import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import time
import threading
from tkinter import messagebox
from wifi_scanner import scan_wifi, block_wifi, get_interfaces, detect_wifi_interface, crack_wifi_password, save_scan_results, load_scan_results, export_to_csv
import string

scan_running = False
scan_paused = False
scan_thread = None
crack_thread = None
scan_results = []

def display_network(network):
    ssid = network['SSID']
    bssid = network['BSSID']
    signal = network['Signal']
    frequency = network['Frequency']
    if not any(bssid in item for item in listbox.get(0, tk.END)):
        listbox.insert(tk.END, f"{ssid} - {bssid} - {signal} - {frequency}")

def update_progress(progress_var, progress_bar, status_label, progress):
    progress_var.set(progress)
    progress_bar.update()
    status_label.config(text=f"Escaneando... {int(progress)}%")

def scan_networks(progress_var, progress_bar, status_label, interface):
    global scan_running, scan_paused, scan_results
    scan_time = 10
    networks = []
    for i in range(scan_time):
        if not scan_running:
            break
        while scan_paused:
            time.sleep(1)
        time.sleep(1)
        new_networks = scan_wifi(interface)
        networks.extend(new_networks)

        app.after(0, update_progress, progress_var, progress_bar, status_label, (i + 1) * 100 / scan_time)

        for network in new_networks:
            app.after(0, display_network, network)

    scan_results = networks
    app.after(0, status_label.config, {"text": "Escaneo completado"})
    app.after(0, progress_var.set, 100)
    app.after(0, progress_bar.update)
    app.after(0, lambda: set_scan_complete())

def set_scan_complete():
    global scan_running
    scan_running = False
    status_label.config(text="Escaneo completado")
    messagebox.showinfo("Información", "Escaneo completado")

def start_scan_thread(interface):
    global scan_running, scan_paused, scan_thread
    if scan_thread and scan_thread.is_alive():
        return
    scan_running = True
    scan_paused = False
    progress_var.set(0)
    status_label.config(text="Iniciando escaneo...")
    scan_thread = threading.Thread(target=scan_networks, args=(progress_var, progress_bar, status_label, interface))
    scan_thread.start()

def stop_scan():
    global scan_running
    scan_running = False
    status_label.config(text="Escaneo detenido")

def pause_scan():
    global scan_paused
    scan_paused = not scan_paused
    status_label.config(text="Escaneo pausado" if scan_paused else "Escaneando...")

def copy_to_clipboard():
    app.clipboard_clear()
    results = listbox.get(0, tk.END)
    results_str = "\n".join(results)
    app.clipboard_append(results_str)
    messagebox.showinfo("Copiado", "Resultados copiados al portapapeles")

def block_selected_network():
    selected = listbox.curselection()
    if not selected:
        messagebox.showwarning("Advertencia", "Seleccione una red de la lista para bloquear.")
        return
    selected_network = listbox.get(selected[0])
    bssid = selected_network.split(' - ')[1]
    block_wifi(bssid)
    messagebox.showinfo("Bloqueo", f"Red {bssid} bloqueada.")

def choose_interface():
    global chosen_interface
    chosen_interface = interface_var.get()
    messagebox.showinfo("Interfaz seleccionada", f"Interfaz {chosen_interface} seleccionada para el escaneo.")

def crack_password_update(password, progress):
    app.after(0, crack_status_label.config, {"text": f"Probando: {password}"})
    app.after(0, crack_progress_var.set, progress)
    app.after(0, crack_progress_bar.update)

def start_crack_thread(ssid, bssid):
    global crack_thread
    if crack_thread and crack_thread.is_alive():
        return  # No iniciar un nuevo hilo si ya hay uno en ejecución
    charset = string.ascii_letters + string.digits + string.punctuation
    min_length = 10
    max_length = 22
    crack_thread = threading.Thread(target=lambda: crack_password_wrapper(ssid, bssid, charset, min_length, max_length))
    crack_thread.start()

def crack_password_wrapper(ssid, bssid, charset, min_length, max_length):
    password = crack_wifi_password(ssid, bssid, crack_password_update, charset, min_length, max_length, delay=2)
    if password:
        messagebox.showinfo("Contraseña Encontrada", f"La contraseña es: {password}")
    else:
        messagebox.showinfo("Contraseña No Encontrada", "No se encontró la contraseña.")

def crack_password():
    selected = listbox.curselection()
    if not selected:
        messagebox.showwarning("Advertencia", "Seleccione una red de la lista para intentar descifrar la contraseña.")
        return
    selected_network = listbox.get(selected[0])
    ssid, bssid = selected_network.split(' - ')
    start_crack_thread(ssid, bssid)

def save_results():
    global scan_results
    if not scan_results:
        messagebox.showwarning("Advertencia", "No hay resultados de escaneo para guardar.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
    if file_path:
        save_scan_results(scan_results, file_path)
        messagebox.showinfo("Guardado", f"Resultados guardados en {file_path}")

def load_results():
    global scan_results
    file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
    if file_path:
        scan_results = load_scan_results(file_path)
        listbox.delete(0, tk.END)
        for network in scan_results:
            display_network(network)
        messagebox.showinfo("Cargado", f"Resultados cargados desde {file_path}")

def export_results():
    global scan_results
    if not scan_results:
        messagebox.showwarning("Advertencia", "No hay resultados de escaneo para exportar.")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if file_path:
        export_to_csv(scan_results, file_path)
        messagebox.showinfo("Exportado", f"Resultados exportados a {file_path}")

app = tk.Tk()
app.title("Wi-Fi Network Scanner")
app.geometry("800x830")

style = ttk.Style()
style.configure("TButton", font=("Segoe UI", 12))
style.configure("TLabel", font=("Segoe UI", 12))
style.configure("TListbox", font=("Segoe UI", 10))
style.configure("TProgressbar", thickness=30)

frame = ttk.Frame(app, padding="20 20 20 20")
frame.pack(fill=tk.BOTH, expand=True)

title_label = ttk.Label(frame, text="Wi-Fi Network Scanner", font=("Segoe UI", 24, "bold"))
title_label.pack(pady=10)

description_label = ttk.Label(frame, text="Detecta, identifica, bloquea y descubre contraseñas de redes Wi-Fi.", font=("Segoe UI", 14))
description_label.pack(pady=5)

separator = ttk.Separator(frame, orient='horizontal')
separator.pack(fill='x', pady=10)

interface_frame = ttk.Frame(frame)
interface_frame.pack(pady=10)

interfaces = get_interfaces()
detected_interface = detect_wifi_interface()

interface_var = tk.StringVar(value=detected_interface if detected_interface else interfaces[0])
interface_label = ttk.Label(interface_frame, text="Seleccionar Interfaz de Red:", font=("Segoe UI", 14))
interface_label.pack(side=tk.LEFT, padx=5)

interface_menu = ttk.OptionMenu(interface_frame, interface_var, *interfaces)
interface_menu.pack(side=tk.LEFT, padx=5)

choose_button = ttk.Button(interface_frame, text="Seleccionar", command=choose_interface)
choose_button.pack(side=tk.LEFT, padx=5)

button_frame1 = ttk.Frame(frame)
button_frame1.pack(pady=10)

start_button = ttk.Button(button_frame1, text="Start Scan", command=lambda: start_scan_thread(interface_var.get()))
start_button.grid(row=0, column=0, padx=5, pady=5)

pause_button = ttk.Button(button_frame1, text="Pause/Resume Scan", command=pause_scan)
pause_button.grid(row=0, column=1, padx=5, pady=5)

stop_button = ttk.Button(button_frame1, text="Stop Scan", command=stop_scan)
stop_button.grid(row=0, column=2, padx=5, pady=5)

copy_button = ttk.Button(button_frame1, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=0, column=3, padx=5, pady=5)

button_frame1.grid_columnconfigure(0, weight=1)
button_frame1.grid_columnconfigure(1, weight=1)
button_frame1.grid_columnconfigure(2, weight=1)
button_frame1.grid_columnconfigure(3, weight=1)

button_frame2 = ttk.Frame(frame)
button_frame2.pack(pady=10)

block_button = ttk.Button(button_frame2, text="Block Selected Network", command=block_selected_network)
block_button.grid(row=0, column=0, padx=5, pady=5)

crack_button = ttk.Button(button_frame2, text="Crack Password", command=crack_password)
crack_button.grid(row=0, column=1, padx=5, pady=5)

save_button = ttk.Button(button_frame2, text="Save Results", command=save_results)
save_button.grid(row=0, column=2, padx=5, pady=5)

load_button = ttk.Button(button_frame2, text="Load Results", command=load_results)
load_button.grid(row=0, column=3, padx=5, pady=5)

export_button = ttk.Button(button_frame2, text="Export to CSV", command=export_results)
export_button.grid(row=0, column=4, padx=5, pady=5)

button_frame2.grid_columnconfigure(0, weight=1)
button_frame2.grid_columnconfigure(1, weight=1)
button_frame2.grid_columnconfigure(2, weight=1)
button_frame2.grid_columnconfigure(3, weight=1)
button_frame2.grid_columnconfigure(4, weight=1)

listbox_label = ttk.Label(frame, text="Redes encontradas:", font=("Segoe UI", 14))
listbox_label.pack(pady=5)

listbox = tk.Listbox(frame, width=80, height=15, font=("Segoe UI", 10))
listbox.pack(pady=10)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(frame, variable=progress_var, maximum=100)
progress_bar.pack(pady=10, fill=tk.X)

status_label = ttk.Label(frame, text="", font=("Segoe UI", 14))
status_label.pack(pady=5)

crack_status_label = ttk.Label(frame, text="", font=("Segoe UI", 14))
crack_status_label.pack(pady=5)

crack_progress_var = tk.DoubleVar()
crack_progress_bar = ttk.Progressbar(frame, variable=crack_progress_var, maximum=100)
crack_progress_bar.pack(pady=10, fill=tk.X)

app.mainloop()
