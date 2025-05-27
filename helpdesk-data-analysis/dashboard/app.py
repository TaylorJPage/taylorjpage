import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Help Desk Dashboard", layout="wide")

# Load data
df = pd.read_csv("../data/tickets.csv", parse_dates=["submitted_at", "resolved_at"])
df["resolution_time"] = (df["resolved_at"] - df["submitted_at"]).dt.total_seconds() / 3600

st.title("📊 Help Desk Ticket Dashboard")

# Category distribution
st.subheader("Tickets by Category")
fig_category = px.histogram(df, x="category", color="category", title="Ticket Volume by Category")
st.plotly_chart(fig_category, use_container_width=True)

# Average resolution time by tech
st.subheader("Average Resolution Time by Technician")
avg_resolution = df.groupby("assigned_to")["resolution_time"].mean().reset_index()
fig_resolution = px.bar(avg_resolution, x="assigned_to", y="resolution_time", title="Avg Resolution Time (hrs)")
st.plotly_chart(fig_resolution, use_container_width=True)
st.write("📂 Loaded Data:")
st.dataframe(df.head())
if df.empty:
    st.warning("The ticket dataset is empty. Check your CSV path or contents.")
else:
    st.plotly_chart(fig_category)
    st.plotly_chart(fig_resolution)
