import os
import shutil
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# --- CONFIGURATION ---
TARGET_HOST = "DESKTOP_Name or IP here" 
BASE_STAGING = r"C:\logs_collection"
# Analysis Window
START_DATE = "2026-02-01"
END_DATE   = "2026-02-02"

# --- 1. SETUP & DISCOVERY ---

def get_host_directory(host):
    host_dir = os.path.join(BASE_STAGING, host)
    os.makedirs(host_dir, exist_ok=True)
    return host_dir

def find_remote_path(host):
    """Locates the Windows Event Log directory on the network."""
    paths = [rf"\\{host}\C$\Windows\System32\winevt\Logs", rf"\\{host}\ADMIN$\System32\winevt\Logs"]
    for p in paths:
        if os.path.exists(p): return p
    return None

# --- 2. EXTRACTION & CLEANING ---

def process_logs_with_timestamps(remote_path, host, folder):
    log_types = ["Application", "Security", "Setup", "System", "ForwardedEvents"]
    now_ts = datetime.now().strftime("%Y%m%d_%H%M")
    today_ts = datetime.now().strftime("%Y%m%d")

    # PowerShell date objects
    pwsh_start = f"(Get-Date '{START_DATE}')"
    pwsh_end   = f"(Get-Date '{END_DATE}').AddDays(1)"

    for log in log_types:
        # Check if we already did this today (Idempotency)
        if any(f.startswith(today_ts) and f.endswith(f"_{log}_Filtered.csv") for f in os.listdir(folder)):
            print(f"⏩ SKIP: {log} already collected today.")
            continue

        src_evtx = os.path.join(remote_path, f"{log}.evtx")
        if not os.path.exists(src_evtx): continue

        local_evtx = os.path.join(folder, f"{now_ts}_{log}.evtx")
        csv_output = os.path.join(folder, f"{now_ts}_{log}_Filtered.csv")

        try:
            print(f"🔄 Extracting {log}...")
            shutil.copy2(src_evtx, local_evtx)
            
            # Filter by date and convert to CSV
            pwsh_cmd = (
                f'Get-WinEvent -Path "{local_evtx}" -MaxEvents 500 -ErrorAction SilentlyContinue | '
                f'Where-Object {{ $_.TimeCreated -ge {pwsh_start} -and $_.TimeCreated -le {pwsh_end} }} | '
                f'Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | '
                f'Export-Csv -Path "{csv_output}" -NoTypeInformation'
            )
            subprocess.run(["powershell", "-Command", pwsh_cmd], check=True)
            print(f"✅ Created: {os.path.basename(csv_output)}")
            
            # Auto-Cleanup: Remove large binary file
            os.remove(local_evtx)
        except Exception as e:
            print(f"❌ Error on {log}: {e}")

# --- 3. ANALYTICS & VISUALIZATION ---

def generate_visual_analytics(host_folder, host_name):
    """Generates charts and fixes the Seaborn FutureWarning."""
    print(f"\n--- Generating Charts for {host_name} ---")
    csv_files = [f for f in os.listdir(host_folder) if f.endswith('_Filtered.csv')]
    
    for file in csv_files:
        try:
            df = pd.read_csv(os.path.join(host_folder, file))
            if df.empty: continue
            
            plt.figure(figsize=(8, 4))
            # Fixed hue/palette warning
            sns.countplot(data=df, x='LevelDisplayName', hue='LevelDisplayName', palette='viridis', legend=False)
            plt.title(f"Log Health: {file.split('_')[2]}")
            plt.tight_layout()
            plt.savefig(os.path.join(host_folder, file.replace('.csv', '.png')))
            plt.show()  # <--- ADD THIS LINE
            plt.close()
            print(f"📊 Charted: {file}")
        except: continue

def create_executive_summary(host_folder, host_name):
    """Generates the final Root Cause report."""
    report_path = os.path.join(host_folder, f"Executive_Summary_{datetime.now().strftime('%Y%m%d')}.txt")
    csv_files = [pd.read_csv(os.path.join(host_folder, f)) for f in os.listdir(host_folder) if f.endswith('_Filtered.csv')]
    
    if not csv_files: return
    master_df = pd.concat(csv_files)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f"SYSTEM HEALTH REPORT: {host_name}\n")
        f.write(f"DATE GENERATED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 50 + "\n\n")
        
        f.write("1. EVENT STATISTICS\n")
        f.write(master_df['LevelDisplayName'].value_counts().to_string() + "\n\n")
        
        f.write("2. TOP CRITICAL ROOT CAUSES\n")
        top_errors = master_df[master_df['LevelDisplayName'].isin(['Error', 'Critical'])]
        if not top_errors.empty:
            f.write(top_errors['Message'].value_counts().head(5).to_string())
        else:
            f.write("No critical errors found.")
            
    print(f"\n📄 EXECUTIVE REPORT CREATED: {report_path}")
     # --- ADD THIS TO SHOW OUTPUT ON SCREEN ---
    print("\n" + "="*50)
    print(f"FINAL SUMMARY FOR {host_name}:")
    print("="*50)
    with open(report_path, 'r') as f:
        print(f.read())


# --- ADD THESE FUNCTIONS TO YOUR logs_collection.py ---

def expert_remediation_advisor(forensic_df):
    """Architect-level Advisor: Uses Keyword & ID matching + Health Scoring."""
    print(f"\n--- 🤖 EXPERT ADVISOR & INTELLIGENCE ---")
    
    # 1. CALCULATE HEALTH SCORE (Thinking out of the box)
    # Start at 100, deduct points for Errors (5) and Warnings (2)
    error_count = len(forensic_df[forensic_df['LevelDisplayName'] == 'Error'])
    warning_count = len(forensic_df[forensic_df['LevelDisplayName'] == 'Warning'])
    
    health_score = 100 - (error_count * 5) - (warning_count * 2)
    health_score = max(0, health_score) # Don't go below 0
    
    color_code = "🟢" if health_score > 90 else "🟡" if health_score > 70 else "🔴"
    print(f"🏥 SERVER HEALTH SCORE: {health_score}/100 {color_code}")

    # 2. BULLETPROOF KNOWLEDGE BASE (Keywords + IDs)
    recommendations = []
    # Convert forensic data to a string to search messages easily
    master_text = " ".join(forensic_df['Message'].astype(str).tolist()).lower()
    
    KB = {
        "secure boot": "ID 17: SBAT Update failure. Apply Microsoft KB5041571.",
        "shadow copies": "ID 12289: VSS storage limit. Run: vssadmin resize shadowstorage /for=C: /maxsize=15%",
        "hosts file": "ID 1008: Hosts file access error. Check Antivirus/Permissions.",
        "profiling api": "ID 2509/1023: .NET Profiler conflict. Disable COR_PROFILER if not used.",
    }

    for key, advice in KB.items():
        if key in master_text:
            recommendations.append(f"• {advice}")

    if recommendations:
        for rec in recommendations:
            print(rec)
    else:
        print("💡 No specific matches found. Manual investigation required.")

def generate_forensic_timeline(host_folder):
    """Unified timeline with uptime detection and clean formatting."""
    print(f"\n--- 🕵️ GENERATING UNIFIED FORENSIC TIMELINE ---")
    all_files = [f for f in os.listdir(host_folder) if f.endswith('_Filtered.csv')]
    combined_list = []

    for f in all_files:
        df = pd.read_csv(os.path.join(host_folder, f))
        if not df.empty:
            df['Log_Source'] = f.split('_')[2]
            combined_list.append(df)

    if not combined_list: 
        print("⚠ No data found to generate timeline.")
        return None
        
    master = pd.concat(combined_list)
    master['TimeCreated'] = pd.to_datetime(master['TimeCreated'], format='mixed', errors='coerce')
    master = master.sort_values(by='TimeCreated')

    # Detect Uptime (Event ID 6005)
    boot_events = master[master['Id'] == 6005]
    if not boot_events.empty:
        print(f"⏱️  SYSTEM UPTIME: Last start recorded at {boot_events['TimeCreated'].max()}")

    forensic_df = master[master['LevelDisplayName'].isin(['Error', 'Critical', 'Warning'])]
    
    timeline_path = os.path.join(host_folder, "Master_Forensic_Timeline.csv")
    forensic_df.to_csv(timeline_path, index=False)
    print(f"✅ Forensic Timeline Saved: {os.path.basename(timeline_path)}")
    
    return forensic_df

# --- 4. MAIN ---

if __name__ == "__main__":
    host_dir = get_host_directory(TARGET_HOST)
    remote_path = find_remote_path(TARGET_HOST)
    
    if remote_path:
        # 1. First, get the fresh data from the host
        process_logs_with_timestamps(remote_path, TARGET_HOST, host_dir)
        
        # 2. Generate the charts and summary
        generate_visual_analytics(host_dir, TARGET_HOST)
        create_executive_summary(host_dir, TARGET_HOST)
        
        # 3. NEW: Create the unified forensic timeline from the fresh CSVs
        master_timeline = generate_forensic_timeline(host_dir)
        
        # 4. NEW: Provide the expert remediation advice
        if master_timeline is not None:
            expert_remediation_advisor(master_timeline)
            
        print(f"\n🚀 Pipeline Complete. All results in: {host_dir}")
    else:
        print(f"❌ Could not connect to {TARGET_HOST}. Check VPN/Network.")

        
            
           