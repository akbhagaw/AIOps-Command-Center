import streamlit as st
import pandas as pd
from engine import LogEngine
from datetime import datetime, time, timedelta

# --- 1. SETUP ---
st.set_page_config(page_title="AIOps Forensic Center", layout="wide")
st.title("🛡️ AIOps: Forensic Command Center")
engine = LogEngine()

if 'forensic_data' not in st.session_state:
    st.session_state.forensic_data = None

# --- 2. SIDEBAR ---
with st.sidebar:
    st.header("1. Target Config")
    # Using an empty value and placeholder as requested to keep it clean
    target_host = st.text_input("Hostname / IP Address", value="", placeholder="Enter Hostname or IP...")
    
    st.divider()
    st.header("2. Analysis Window")
    c1, c2 = st.columns(2)
    start_date = c1.date_input("Start Date", datetime.now() - timedelta(days=1))
    start_time = c2.time_input("Start Time", time(0, 0))
    
    c3, c4 = st.columns(2)
    end_date = c3.date_input("End Date", datetime.now())
    end_time = c4.time_input("End Time", time(23, 59))
    
    analyze_btn = st.button("🚀 Run Analysis", use_container_width=True)

# --- 3. SMARTER L3 TRIAGE LOGIC ---
def process_forensic_clusters(df):
    # L3 Noise Filter: Words that sound scary but are usually harmless
    noise_filter = ['vss service is shutting down', 'idle timeout', 'successfully', 'entering sleep']

    def assign_priority(row):
        msg = str(row['Message']).lower()
        level = row['LevelDisplayName']
        
        # Rule 1: If it's in our noise filter, it's ALWAYS Blue
        if any(k in msg for k in noise_filter):
            return "🔵 NORMAL"
            
        # Rule 2: Killer Keywords make any level URGENT
        killer_keywords = ['stopped', 'failed', 'denied', 'critical', 'aborted', 'disk error']
        if level == 'Critical' or any(k in msg for k in killer_keywords):
            return "🔴 URGENT"
        
        # Rule 3: Map remaining levels to appropriate L3 priorities
        if level == 'Error':
            return "🟡 HIGH"
        if level == 'Warning':
            return "🟠 MEDIUM"
            
        return "🔵 NORMAL"

    # Cluster identical events
    clustered = df.groupby(['Id', 'LevelDisplayName', 'Message']).size().reset_index(name='Total_Count')
    clustered['Priority'] = clustered.apply(assign_priority, axis=1)
    
    # Sort order: Red -> Yellow -> Orange -> Blue
    sort_map = {"🔴 URGENT": 0, "🟡 HIGH": 1, "🟠 MEDIUM": 2, "🔵 NORMAL": 3}
    clustered['sort_idx'] = clustered['Priority'].map(sort_map)
    
    return clustered.sort_values(by=['sort_idx', 'Total_Count'], ascending=[True, False]).drop(columns=['sort_idx'])

def style_priority(val):
    colors = {
        "🔴 URGENT": "background-color: #ffcccc; color: black; font-weight: bold",
        "🟡 HIGH": "background-color: #fff3cd; color: black; font-weight: bold",
        "🟠 MEDIUM": "background-color: #ffe0b2; color: black; font-weight: bold",
        "🔵 NORMAL": "background-color: #e1f5fe; color: black"
    }
    return colors.get(val, "")

# --- 4. EXECUTION ---
if analyze_btn:
    if not target_host:
        st.error("⚠️ Please enter a Hostname or IP.")
    else:
        start_dt = datetime.combine(start_date, start_time)
        end_dt = datetime.combine(end_date, end_time)
        
        with st.status(f"Analyzing {target_host}...", expanded=True) as status:
            success, result, status_msg = engine.run_collection(target_host)
            if success:
                raw_df = engine.get_forensics(result)
                filtered_df = raw_df[(raw_df['TimeCreated'] >= start_dt) & (raw_df['TimeCreated'] <= end_dt)]
                st.session_state.forensic_data = process_forensic_clusters(filtered_df)
                st.session_state.total_count = len(filtered_df)
                status.update(label="✅ Analysis Complete", state="complete", expanded=False)
            else:
                st.error(result)

# --- 5. DISPLAY ---
if st.session_state.forensic_data is not None:
    df = st.session_state.forensic_data
    
    m1, m2, m3 = st.columns(3)
    # Health calculation: Now only Red/Yellow impact health significantly
    urgents = len(df[df['Priority'] == "🔴 URGENT"])
    highs = len(df[df['Priority'] == "🟡 HIGH"])
    health = max(0, 100 - (urgents * 20) - (highs * 5))
    
    m1.metric("System Health", f"{health}%")
    m2.metric("Urgent Patterns", urgents)
    m3.metric("Total Raw Logs", st.session_state.total_count)

    st.subheader("⚠️ Actionable Hotspots (Urgent & High)")
    hotspots = df[df['Priority'].isin(["🔴 URGENT", "🟡 HIGH"])].head(10)
    st.table(hotspots[['Priority', 'Total_Count', 'Message']])

    st.subheader(f"🕵️ Clustered Forensic Timeline: {target_host}")
    st.dataframe(df.style.applymap(style_priority, subset=['Priority']), use_container_width=True)