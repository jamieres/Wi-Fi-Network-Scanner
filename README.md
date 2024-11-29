# Wi-Fi Network Scanner

**Wi-Fi Network Scanner** is a tool designed to detect, identify and block Wi-Fi networks. It also allows you to try to crack passwords for selected networks using a brute force method. The graphical user interface (GUI) is built with Tkinter, making it easy to interact with and use the program.

## Features

- **Wi-Fi Network Detection**: Scans and displays available Wi-Fi networks in the environment.
- **Network Identification**: Displays SSID, BSSID, signal and frequency of detected networks.
- **Network Blocking**: Allows you to block selected Wi-Fi networks.
- **Password Cracking**: Uses brute force to try to crack passwords for selected networks.
- **Save and Load Results**: Saves and loads scan results to JSON files.
- **Export Results**: Exports scan results to CSV files.

## Dependencies

For the program to work properly, the following dependencies must be installed:

- `pywifi`: Library used to interact with Wi-Fi interfaces.
- `tkinter`: Python standard library for creating graphical user interfaces.
- `comtypes`: Library required for `pywifi` functionality on Windows.

You can install these dependencies using pip:
pip install pywifi
pip install comtypes

## Installation and Execution
Clone this repository to your local machine.
Navigate to the project directory.

## Run the wifi_gui.py file:
python wifi_gui.py

## Usage
- Start Scan: Begins the process of scanning Wi-Fi networks using the selected interface.
- Pause/Resume Scan: Pauses or resumes the ongoing scan.
- Stop Scan: Stops the scanning process.
- Copy to Clipboard: Copies the scan results to the clipboard.
- Lock selected network: Locks the Wi-Fi network selected in the list.
- Crack password: Starts the password cracking process for the selected network.
- Save results: Saves the scan results to a JSON file.
- Load results: Loads scan results from a JSON file.
- Export to CSV: Exports the scan results to a CSV file.

## Considerations
The program may temporarily affect the Wi-Fi connection of the device from which it is run, especially during the password cracking process. It is recommended to use this program in a controlled environment and not on public Wi-Fi networks.

## Contributions
Contributions are welcome. Please open an issue or pull request for any improvements or corrections.
jamieres-at-gmail-dot-com

## License
This project is licensed under the MIT License.
