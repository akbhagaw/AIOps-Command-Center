import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from engine import LogEngine
from datetime import datetime, time, timedelta

# --- CONFIG ---
st.set_page_config(page_title="AIOps Command Center", layout="wide")
st.title("🛡️ AIOps: Forensic Command Center")
engine = LogEngine()

# --- SIDEBAR ---
with st.sidebar:
    st.header("1. Target Config")
    target_host = st.text_input("Hostname", value="DESKTOP-E50N2KH")
    
    st.divider()
    st.header("2. Analysis Window")
    c1, c2 = st.columns(2)
    start_date = c1.date_input("Start Date", datetime.now() - timedelta(days=1))
    start_time = c2.time_input("Start Time", time(0, 0))
    
    c3, c4 = st.columns(2)
    end_date = c3.date_input("End Date", datetime.now())
    end_time = c4.time_input("End Time", time(23, 59))
    
    analyze_btn = st.button("🚀 Run Analysis", use_container_width=True)

# --- HELPERS ---
def get_priority(row):
    msg = str(row['Message']).lower()
    level = str(row['LevelDisplayName'])
    urgent_words = ['denied', 'failed', 'critical', 'stopped', 'aborted', 'error code: 0x']
    if level == 'Critical' or any(word in msg for word in urgent_words):
        return "🔴 URGENT"
    elif level == 'Error':
        return "🟡 HIGH"
    return "🔵 NORMAL"

def style_priority(val):
    colors = {"🔴 URGENT": "#ffcccc", "🟡 HIGH": "#fff3cd", "🔵 NORMAL": "#e1f5fe"}
    return f'background-color: {colors.get(val, "")}; color: black'

# --- MAIN LOGIC ---
if analyze_btn:
    start_dt = datetime.combine(start_date, start_time)
    end_dt = datetime.combine(end_date, end_time)
    
    if end_dt <= start_dt:
        st.error("❌ End time must be after Start time.")
    else:
        with st.spinner("Analyzing logs..."):
            success, result, status_msg = engine.run_collection(target_host)
            st.toast(status_msg)
            
        if success:
            df = engine.get_forensics(result)
            # Filter
            df = df[(df['TimeCreated'] >= start_dt) & (df['TimeCreated'] <= end_dt)].reset_index(drop=True)

            if df.empty:
                st.warning("No logs found in this window.")
            else:
                df['Priority'] = df.apply(get_priority, axis=1)
                
                # KPIs
                errs = len(df[df['LevelDisplayName'] == 'Error'])
                crits = len(df[df['LevelDisplayName'] == 'Critical'])
                health = max(0, 100 - (errs * 5) - (crits * 20))
                
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Health Score", f"{health}%")
                m2.metric("Critical Errors", crits + errs)
                m3.metric("Warnings", len(df[df['LevelDisplayName'] == 'Warning']))
                m4.metric("Total Events", len(df))

                # Visuals
                st.subheader("📊 Event Distribution")
                fig, ax = plt.subplots(figsize=(10, 3))
                sns.countplot(data=df, x='LevelDisplayName', hue='LevelDisplayName', palette='rocket', ax=ax, legend=False)
                for container in ax.containers:
                    ax.bar_label(container, padding=3, fontweight='bold')
                st.pyplot(fig)

                # Table
                st.subheader("🕵️ Forensic Timeline")
                st.dataframe(df.style.applymap(style_priority, subset=['Priority']), use_container_width=True)
                
                # Export
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Download CSV", csv, "forensics.csv", "text/csv")
        else:
            st.error(f"Error: {result}")