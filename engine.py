import os, shutil, subprocess, pandas as pd
from datetime import datetime

class LogEngine:
    def __init__(self, base_path=r"C:\logs_collection"):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)

    def get_host_dir(self, host):
        path = os.path.join(self.base_path, host)
        os.makedirs(path, exist_ok=True)
        return path

    def find_remote_path(self, host):
        paths = [rf"\\{host}\C$\Windows\System32\winevt\Logs", rf"\\{host}\ADMIN$\System32\winevt\Logs"]
        for p in paths:
            if os.path.exists(p): return p
        return None

    def run_collection(self, host):
        folder = self.get_host_dir(host)
        log_types = ["Application", "Security", "Setup", "System"]
        
        # Idempotency: If today's files exist, don't re-download
        today_prefix = datetime.now().strftime("%Y%m%d")
        existing = [f for f in os.listdir(folder) if f.startswith(today_prefix) and f.endswith('_Filtered.csv')]
        if len(existing) >= len(log_types):
            return True, folder, "📦 Using local cache."

        remote = self.find_remote_path(host)
        if not remote: return False, "Host Unreachable", "❌ Connection Failed"
        
        now_ts = datetime.now().strftime("%Y%m%d_%H%M")
        for log in log_types:
            src = os.path.join(remote, f"{log}.evtx")
            if not os.path.exists(src): continue
            local_evtx = os.path.join(folder, f"{log}.evtx")
            csv_output = os.path.join(folder, f"{now_ts}_{log}_Filtered.csv")
            
            shutil.copy2(src, local_evtx)
            pwsh = f'Get-WinEvent -Path "{local_evtx}" -MaxEvents 1000 | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -Path "{csv_output}" -NoTypeInformation'
            subprocess.run(["powershell", "-Command", pwsh], capture_output=True)
            if os.path.exists(local_evtx): os.remove(local_evtx)
            
        return True, folder, "🚀 Fresh logs collected."

    def get_forensics(self, folder):
        csv_files = [f for f in os.listdir(folder) if f.endswith('_Filtered.csv')]
        if not csv_files: return None
        master = pd.concat([pd.read_csv(os.path.join(folder, f)) for f in csv_files]).reset_index(drop=True)
        master['TimeCreated'] = pd.to_datetime(master['TimeCreated'], format='mixed', errors='coerce')
        return master.sort_values('TimeCreated', ascending=False)