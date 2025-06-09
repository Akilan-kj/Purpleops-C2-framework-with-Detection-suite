import os
import psutil
import time
import sys
import requests
import yara
import requests
import pyfiglet
import random
import hashlib
from tabulate import tabulate
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)

FONTS = ["speed","graffiti"]

def print_banner():
    font = random.choice(FONTS)
    ascii_banner = pyfiglet.figlet_format(" C2 Detection Suite", font=font)
    author = pyfiglet.figlet_format("By - Akil", font="smslant")
    
    print(Fore.CYAN + ascii_banner)
    print(Fore.YELLOW + author)
    print(Fore.MAGENTA + "=" * 60 + Style.RESET_ALL)
print_banner()

VIRUSTOTAL_API_KEY = "4fbc14a1c7a64691c2b590d416436559469cd8cdf5d8eced798771cb1564a0a8"

C2_INDICATORS = ["api.github.com", "raw.githubusercontent.com", "github.com"]


YARA_RULE_PATH = os.path.join(os.path.dirname(__file__), "c2_rules.yar")

try:
    yara_rule = yara.compile(filepath=YARA_RULE_PATH)
    print(f"{Fore.GREEN}[ ✔  ] Powered With YARA Rules - Supercharge Your Detection !")
except yara.SyntaxError as e:
    print(f"[ X ] YARA syntax error: {e}")
    sys.exit(1)
except yara.Error as e:
    print(f"[ X ] YARA error: {e}")
    sys.exit(1)

def progress_bar(message, duration=5):
    
    print(Fore.WHITE + message)
    for _ in tqdm(range(duration), desc="Progress", unit="sec", ncols=80, colour="cyan"):
        time.sleep(1)
    print("\n")

def detect_c2_agent():
    detected = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            process_name = proc.info['name'].lower()
            exe_path = proc.info['exe']
            if not exe_path or not os.path.isfile(exe_path):
                continue
            yara_matches = yara_rule.match(filepath=exe_path)
            cmdline = " ".join(proc.info.get('cmdline', []) or [])
            if any(domain in cmdline for domain in C2_INDICATORS):
                yara_matches.append("GitHub API Detected in Process Execution")
            if yara_matches:
                detected.append([
                    proc.info['pid'],
                    proc.info['name'],
                    exe_path,
                    " ⚠️ C2 Agent Detected!",
                    ", ".join([match.rule for match in yara_matches])
                ])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError):
            continue
    return detected 

def display_detected_agents(detected_agents):
    progress_bar("🔎 Scanning for Possible C2 Agent", 8)  
    if detected_agents:
        formatted_agents = [
            [
                agent[0],  
                Fore.RED + agent[1] + Style.RESET_ALL,  
                agent[2],  
                Fore.RED + agent[3] + Style.RESET_ALL, 
                agent[4]   
            ]
            for agent in detected_agents
        ]
        print(Style.RESET_ALL)
        print(tabulate(formatted_agents, headers=["PID", "Process Name", "File Path", "Alert", "YARA Matches"], tablefmt="pretty"))
        print(Fore.RED + "\n🚨 A possible C2 agent is running on your system ! " + Style.RESET_ALL + Fore.YELLOW + "\n⚠️  ACTION REQUIRED:" + Style.RESET_ALL+ Fore.WHITE + " Perform Deep Scan to confirm ❗"+ Style.RESET_ALL)
    else:
        print(f"{Fore.GREEN}[✅] No active C2 agents found.")



def hash_file(filepath):
    """Generate SHA-256 hash of a file"""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as file:
            while chunk := file.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None
        
def virus_total_scan(filepath):
    """Perform a deep scan using VirusTotal API and display detection report"""
    progress_bar("🔎 Deep Scan against Multiple AV", 10)

    file_hash = hash_file(filepath)  
    if not file_hash:
        print(Fore.RED + "[X] ERROR: Cannot compute file hash.")
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            scan_data = response.json()
            stats = scan_data['data']['attributes']['last_analysis_stats']
            results = scan_data['data']['attributes']['last_analysis_results']
            total_scanners = sum(stats.values())
            detection_score = stats.get('malicious', 0) + stats.get('suspicious', 0)
            print(f"{Fore.WHITE}\n========== 📃 Deep Scan Report  ===========")
            print(f"❗ Detection Score: {Fore.RED if detection_score > 0 else Fore.GREEN}{detection_score}{Style.RESET_ALL}/{total_scanners}\n")

            sorted_results = sorted(results.items(), key=lambda x: x[1]['category'] != 'malicious')
            table_data = []
            for engine, result in sorted_results:
                category = result["category"]
                if category == "malicious":
                    color = Fore.RED
                    category_name = "Trojan"
                elif category == "suspicious":
                    color = Fore.YELLOW
                    category_name = "Suspicious"
                else:
                    color = Fore.GREEN
                    category_name = "Clean"
                res_text = result["result"] if result["result"] else "N/A"
                table_data.append([color + engine + Style.RESET_ALL, color + category_name + Style.RESET_ALL, color + res_text + Style.RESET_ALL])
            if table_data:
                print(tabulate(table_data, headers=["Engine", "Category", "Result"], tablefmt="pretty"))
            else:
                print(f"{Fore.GREEN}✅ No detections found!")
            
            if detection_score > 0:
                print(Fore.RED + "\n🚨 ACTION RECOMMENDED: Eradicate the detected C2 agent immediately!")
            else:
                print(Fore.GREEN + "\n✅ File appears clean.")
        else:
            print(f"{Fore.YELLOW}[!] VirusTotal scan report unavailable.")
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[X] ERROR: VirusTotal API request timed out.")

def eradicate_c2_agent():
    """🚨 Automatically terminate detected C2 agents and remove their files"""
    detected_agents = detect_c2_agent()  

    if not detected_agents:
        print(Fore.GREEN + "✅ No C2 agents found. Nothing to remove.")
        return

    for agent in detected_agents:
        pid, name, filepath, _, _ = agent  
        progress_bar(f"🚫 Terminating {name} (PID: {pid})...", 5)
        try:
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=5)
            print(f"{Fore.GREEN}✅ Process {pid} ({name}) has been terminated.")
        except Exception as e:
            print(f"{Fore.RED}[X] ERROR terminating process {pid}: {e}")

        progress_bar(f"⛔ Removing {filepath}...", 5)
        try:
            os.remove(filepath)
            print(f"{Fore.GREEN}✅ File {filepath} has been removed.")
        except Exception as e:
            print(f"{Fore.RED}[X] ERROR removing file {filepath}: {e}")

def main():
    while True:
        print("[1] Detect C2 Agent")
        print("[2] Deep Scan Against Multiple AV ")
        print("[3] Eradicate Detected Process")
        print("[4] Exit")
        choice = input(f"{Fore.YELLOW}Enter your choice: ")

        if choice == "1":
            detected=detect_c2_agent()
            display_detected_agents(detected)
        elif choice == "2":
            filepath = input(f"{Fore.YELLOW}Enter file path to scan: ")
            virus_total_scan(filepath)
        elif choice == "3":
            eradicate_c2_agent()
        elif choice == "4":
            print("Bye,Stay Safe❗")
            sys.exit()
        else:
            print(f"{Fore.RED}❌ Invalid choice.")

if __name__ == "__main__":
    main()