import os
import subprocess
import requests
import zipfile
from pathlib import Path
import time
import ctypes
import sys
import hashlib
import json

SERVICE_NAME = "GoodbyeDPIService"
LOCAL_PATH = Path(r"C:\path\to")
EXE_PATH = LOCAL_PATH / "GoodbyeDPI.exe"
REPO_URL = "https://api.github.com/repos/ValdikSS/GoodbyeDPI/releases/latest"
VIRUSTOTAL_API_KEY = "6403239881a50763b1cd2d467d12bbb1d1fda12418149de584abc843c04b8809"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"

CMD_FILES = [
    "0_russia_update_blacklist_file.cmd",
    "1_russia_blacklist.cmd",
    "1_russia_blacklist_dnsredir.cmd",
    "2_any_country.cmd",
    "2_any_country_dnsredir.cmd"
]

DEPENDENCIES = ["WinDivert.dll", "WinDivert64.sys", "russia-blacklist.txt"]

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_cmd_files():
    for cmd_file in CMD_FILES:
        cmd_path = LOCAL_PATH / cmd_file
        if cmd_path.exists():
            print(f"Executing {cmd_file}...")
            subprocess.run(["cmd.exe", "/c", str(cmd_path)], check=True)
        else:
            print(f"{cmd_file} not found!")

def check_dependencies():
    for dependency in DEPENDENCIES:
        dep_path = LOCAL_PATH / dependency
        if not dep_path.exists():
            print(f"Dependency {dependency} is missing!")
            return False
    return True

def install_service():
    print("Installing service...")
    subprocess.run([
        "sc", "create", SERVICE_NAME, "binPath=", str(EXE_PATH), "start=", "auto"
    ], check=True)
    subprocess.run(["sc", "start", SERVICE_NAME], check=True)

def get_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def check_virustotal(file_path):
    print("Checking file on VirusTotal...")
    file_hash = get_file_hash(file_path)
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(f"{VIRUSTOTAL_URL}/{file_hash}", headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        if json_response["data"]["attributes"]["last_analysis_stats"]["malicious"] > 10:
            print("File detected as malicious by more than 10 engines. Aborting update.")
            return False
        else:
            print("File is safe.")
            return True
    else:
        print("File not found on VirusTotal. Uploading for analysis...")
        files = {'file': open(file_path, 'rb')}
        response = requests.post(VIRUSTOTAL_URL, headers=headers, files=files)
        if response.status_code == 200:
            json_response = response.json()
            file_id = json_response["data"]["id"]
            print("File uploaded. Waiting for analysis...")
            time.sleep(60)  # Wait for VirusTotal to analyze the file
            response = requests.get(f"{VIRUSTOTAL_URL}/{file_id}", headers=headers)
            json_response = response.json()
            if json_response["data"]["attributes"]["last_analysis_stats"]["malicious"] > 10:
                print("File detected as malicious by more than 10 engines. Aborting update.")
                return False
            else:
                print("File is safe.")
                return True
        else:
            print("Failed to upload file to VirusTotal.")
            return False

def update_program():
    print("Checking for updates...")
    response = requests.get(REPO_URL)
    latest_version = response.json()["tag_name"]
    version_file_path = LOCAL_PATH / "version.txt"

    current_version = ""
    if version_file_path.exists():
        with open(version_file_path, "r") as version_file:
            current_version = version_file.read().strip()

    if latest_version != current_version:
        print(f"New version available: {latest_version}. Updating...")
        download_url = next(
            asset["browser_download_url"] for asset in response.json()["assets"] if asset["name"].endswith(".zip")
        )
        zip_path = LOCAL_PATH / "GoodbyeDPI.zip"
        with requests.get(download_url, stream=True) as r:
            with open(zip_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

        if check_virustotal(zip_path):
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(LOCAL_PATH)

            with open(version_file_path, "w") as version_file:
                version_file.write(latest_version)

            subprocess.run(["sc", "stop", SERVICE_NAME], check=True)
            subprocess.run(["sc", "start", SERVICE_NAME], check=True)
        else:
            print("Update aborted due to VirusTotal check.")
    else:
        print("No new version available.")

def main():
    if not is_admin():
        print("This script must be run as administrator.")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

    if not check_dependencies():
        print("Some dependencies are missing. Exiting script.")
        sys.exit()

    install_service()
    run_cmd_files()
    update_program()
    print("Script completed.")

if __name__ == "__main__":
    main()
