import streamlit as st
import matplotlib.pyplot as plt
import os
import time

st.set_page_config(
    page_title="Network Guardian",
    layout="wide"
)

st.title("🛡️ Network Guardian Dashboard")

# -----------------------------------
# Alerts Section
# -----------------------------------

st.header("🚨 Security Alerts")

alerts_file = "logs/alerts.txt"

if os.path.exists(alerts_file):

    with open(alerts_file, "r") as file:

        alerts = file.readlines()

    if alerts:

        for alert in reversed(alerts[-10:]):

            st.error(alert)

    else:

        st.success("No alerts detected.")

else:

    st.warning("alerts.txt not found.")

# -----------------------------------
# Packet Capture Status
# -----------------------------------

st.header("📦 Packet Capture Status")

pcap_file = "captures/network_traffic.pcap"

if os.path.exists(pcap_file):

    size = os.path.getsize(pcap_file)

    st.metric(
        label="PCAP File Size",
        value=f"{size / 1024:.2f} KB"
    )

else:

    st.warning("No PCAP file found.")

# -----------------------------------
# Protocol Statistics
# -----------------------------------

st.header("📊 Protocol Statistics")

stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "DNS": 0
}

stats_file = "logs/stats.txt"

if os.path.exists(stats_file):

    with open(stats_file, "r") as file:

        lines = file.readlines()

        for line in lines:

            protocol, count = line.strip().split(":")

            stats[protocol] = int(count)

# Display metrics
col1, col2, col3, col4 = st.columns(4)

col1.metric("TCP", stats["TCP"])
col2.metric("UDP", stats["UDP"])
col3.metric("ICMP", stats["ICMP"])
col4.metric("DNS", stats["DNS"])

# -----------------------------------
# Traffic Graph
# -----------------------------------

st.header("📈 Traffic Analysis")

fig, ax = plt.subplots()

ax.bar(
    stats.keys(),
    stats.values()
)

ax.set_xlabel("Protocol")
ax.set_ylabel("Packets")
ax.set_title("Network Traffic Distribution")

st.pyplot(fig)

# -----------------------------------
# Monitoring Status
# -----------------------------------

st.header("📡 Monitoring Status")

st.success("Network Guardian is Running")

# -----------------------------------
# Auto Refresh
# -----------------------------------

time.sleep(2)
st.rerun()