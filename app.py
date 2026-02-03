import streamlit as st
import pandas as pd
from engine import LogEngine
from datetime import datetime, time, timedelta

# --- 1. INITIALIZATION ---
st.set_page_config(page_title="AIOps Fleet Command", layout="wide", page_icon="🛡️")
engine = LogEngine()

# Ensure all session variables exist to prevent NameErrors
if 'forensic_data' not in st.session_state:
    st.session_state.forensic_data = None
if 'fleet_list' not in st.session_state:
    st.session_state.fleet_list = []
if 'total_count' not in st.session_state:
    st.session_state.total_count = 0

# --- 2. L3 CORE LOGIC (Defined before UI) ---

def process_forensic_clusters(df):
    """
    Groups identical logs by Host and ID to reduce noise.
    Implements the L3 Smart Triage logic.
    """
    # Known noise: Scents that look like failures but aren't (L3 Filter)
    noise_filter = [
        'vss service is shutting down', 
        'idle timeout', 
        'successfully', 
        'entering sleep',
        'hibernate from sleep'
    ]

    def assign_priority(row):
        msg = str(row['Message']).lower()
        level = row['LevelDisplayName']
        
        # 1. Noise Filter (Always Blue)
        if any(k in msg for k in noise_filter):
            return "🔵 NORMAL"
            
        # 2. Killer Keywords (Always Red/Urgent regardless of OS level)
        killer_keywords = ['stopped', 'failed', 'denied', 'critical', 'aborted', 'disk error']
        if level == 'Critical' or any(k in msg for k in killer_keywords):
            return "🔴 URGENT"
        
        # 3. Standard Mapping
        if level == 'Error':
            return "🟡 HIGH"
        if level == 'Warning':
            return "🟠 MEDIUM"
            
        return "🔵 NORMAL"

    # Grouping logic
    clustered = df.groupby(['Hostname', 'Id', 'LevelDisplayName', 'Message']).size().reset_index(name='Total_Count')
    clustered['Priority'] = clustered.apply(assign_priority, axis=1)
    
    # Sort: Urgent -> High -> Medium -> Normal
    sort_map = {"🔴 URGENT": 0, "🟡 HIGH": 1, "🟠 MEDIUM": 2, "🔵 NORMAL": 3}
    clustered['sort_idx'] = clustered['Priority'].map(sort_map)
    
    return clustered.sort_values(by=['sort_idx', 'Total_Count'], ascending=[True, False]).drop(columns=['sort_idx'])

def style_priority(val):
    """Applies CSS colors to the Priority column."""
    colors = {
        "🔴 URGENT": "background-color: #ffcccc; color: black; font-weight: bold",
        "🟡 HIGH": "background-color: #fff3cd; color: black; font-weight: bold",
        "🟠 MEDIUM": "background-color: #ffe0b2; color: black; font-weight: bold",
        "🔵 NORMAL": "background-color: #e1f5fe; color: black"
    }
    return colors.get(val, "")

# --- 3. UI LAYOUT ---

st.title("🛡️ AIOps: Fleet Forensic Command Center")

tab1, tab2 = st.tabs(["📊 Live Dashboard", "🖥️ Fleet Manager"])

# --- TAB: FLEET MANAGER ---
with tab2:
    st.header("🖥️ Target Fleet Configuration")
    st.info("Define the servers and desktops you want to monitor.")
    
    col_a, col_b = st.columns([1, 2])
    with col_a:
        new_host = st.text_input("Add Host (Hostname or IP)", placeholder="e.g. 192.168.1.50")
        if st.button("➕ Add to Fleet"):
            if new_host and new_host not in st.session_state.fleet_list:
                st.session_state.fleet_list.append(new_host)
                st.rerun()
    
    with col_b:
        st.write("### Active Targets")
        if not st.session_state.fleet_list:
            st.write("Fleet is currently empty.")
        for i, host in enumerate(st.session_state.fleet_list):
            c1, c2 = st.columns([3, 1])
            c1.code(host)
            if c2.button("🗑️ Remove", key=f"rm_{i}"):
                st.session_state.fleet_list.pop(i)
                st.rerun()

# --- TAB: LIVE DASHBOARD ---
with tab1:
    if not st.session_state.fleet_list:
        st.warning("👈 Please add hosts in the 'Fleet Manager' tab to begin.")
    else:
        # Control Bar
        c1, c2, c3 = st.columns([2, 2, 1])
        start_date = c1.date_input("Start Date", datetime.now() - timedelta(days=1))
        end_date = c2.date_input("End Date", datetime.now())
        
        if c3.button("🚀 Run Fleet Sync", use_container_width=True):
            all_data = []
            start_dt = datetime.combine(start_date, time(0, 0))
            end_dt = datetime.combine(end_date, time(23, 59))
            
            with st.status("Gathering Fleet Intelligence...", expanded=True) as status:
                for host in st.session_state.fleet_list:
                    st.write(f"📡 Connecting to {host}...")
                    success, result, _ = engine.run_collection(host)
                    if success:
                        df = engine.get_forensics(result)
                        # Filter by date range
                        df = df[(df['TimeCreated'] >= start_dt) & (df['TimeCreated'] <= end_dt)]
                        df['Hostname'] = host 
                        all_data.append(df)
                
                if all_data:
                    master_df = pd.concat(all_data, ignore_index=True)
                    st.session_state.forensic_data = process_forensic_clusters(master_df)
                    st.session_state.total_count = len(master_df)
                    status.update(label="✅ Analysis Complete", state="complete")
                else:
                    status.update(label="❌ No Data Found", state="error")

        # --- RESULTS DISPLAY ---
        if st.session_state.forensic_data is not None:
            df = st.session_state.forensic_data
            
            # KPI Metrics
            m1, m2, m3 = st.columns(3)
            urgents = len(df[df['Priority'] == "🔴 URGENT"])
            stability = max(0, 100 - (urgents * 10))
            
            m1.metric("Fleet Stability Index", f"{stability}%")
            m2.metric("Critical Patterns", urgents)
            m3.metric("Total Logs Processed", st.session_state.total_count)

            # Explainer
            with st.expander("ℹ️ How is Stability calculated?"):
                st.write(f"""
                - **Current Score: {stability}%**
                - This score measures current system health, not probability of a crash.
                - We identified **{urgents} unique Urgent patterns**.
                - Each unique pattern found across the fleet subtracts **10%** from the score.
                - **100%** means no critical failures detected in the scanned window.
                """)

            # Hotspots
            st.subheader("🚨 Priority Hotspots")
            hotspots = df[df['Priority'].isin(["🔴 URGENT", "🟡 HIGH"])].head(10)
            if not hotspots.empty:
                st.table(hotspots[['Hostname', 'Priority', 'Total_Count', 'Message']])
            else:
                st.success("Fleet is stable. No high-priority hotspots found.")

            # Full Data
            st.subheader("🔍 All Clustered Events")
            st.dataframe(
                df.style.applymap(style_priority, subset=['Priority']), 
                use_container_width=True
            )