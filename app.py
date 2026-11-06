
import streamlit as st
import pandas as pd
import uuid
from pathlib import Path

# =====================================
# 1. PAGE CONFIGURATION
# =====================================

st.set_page_config(
    page_title="E-Wallet Security",
    page_icon="🛡️",
    layout="wide"
)

CSV_FILE = Path("transactions.csv")

HIGH_AMOUNT_LIMIT = 5000
BURST_LIMIT = 5
BURST_MINUTES = 10


# =====================================
# 2. DASHBOARD STYLE
# =====================================

st.markdown("""
<style>
.stApp {
    background: #080F20;
}
.block-container {
    max-width: 1450px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}
h1, h2, h3, h4 {
    color: #F0F6FF !important;
}
p, label, .stCaption {
    color: #A5B9D4;
}
div[data-testid="stMetric"] {
    background: #142440;
    border: 1px solid #263D5D;
    border-radius: 14px;
    padding: 18px;
}
div[data-testid="stMetricValue"] {
    color: #54A9FF;
}
div[data-testid="stMetricLabel"] {
    color: #A5B9D4;
}
div[data-testid="stDataFrame"] {
    border: 1px solid #263D5D;
    border-radius: 12px;
}
.stButton button,
.stFormSubmitButton button {
    background: #246CC5;
    color: white;
    border: none;
    border-radius: 9px;
}
.stButton button:hover,
.stFormSubmitButton button:hover {
    background: #368FFF;
    color: white;
}
</style>
""", unsafe_allow_html=True)


# =====================================
# 3. LOAD CSV DATA
# =====================================

def load_data():

    if not CSV_FILE.exists():
        raise FileNotFoundError(
            "transactions.csv was not found."
        )

    df = pd.read_csv(CSV_FILE)

    required_columns = [
        "transaction_id",
        "wallet_id",
        "amount",
        "merchant",
        "channel",
        "timestamp"
    ]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(
                f"Missing CSV column: {column}"
            )

    df["amount"] = pd.to_numeric(
        df["amount"], errors="coerce"
    ).fillna(0)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    return df


# =====================================
# 4. THREAT DETECTION
# =====================================

def detect_threats(df):

    df = df.copy()

    statuses = []
    reasons = []

    for _, row in df.iterrows():

        transaction_reasons = []

        # Rule 1: High Transaction Amount

        if row["amount"] > HIGH_AMOUNT_LIMIT:
            transaction_reasons.append(
                "High transaction amount"
            )

        # Rule 2: Multiple Transactions

        if pd.notna(row["timestamp"]):

            start_time = (
                row["timestamp"]
                - pd.Timedelta(minutes=BURST_MINUTES)
            )

            wallet_transactions = df[
                (df["wallet_id"] == row["wallet_id"]) &
                (df["timestamp"] >= start_time) &
                (df["timestamp"] <= row["timestamp"])
            ]

            if len(wallet_transactions) > BURST_LIMIT:
                transaction_reasons.append(
                    "Multiple transactions in 10 minutes"
                )

        if transaction_reasons:
            statuses.append("Suspicious")
            reasons.append(", ".join(transaction_reasons))
        else:
            statuses.append("Normal")
            reasons.append("No threat detected")

    df["status"] = statuses
    df["reason"] = reasons

    return df


# =====================================
# 5. LOAD AND ANALYZE
# =====================================

try:
    data = load_data()
    data = detect_threats(data)

except (FileNotFoundError, ValueError, pd.errors.ParserError) as error:
    st.error(f"Unable to load transaction data: {error}")
    st.stop()

total = len(data)

suspicious = len(
    data[data["status"] == "Suspicious"]
)

normal = len(
    data[data["status"] == "Normal"]
)

wallets = data["wallet_id"].nunique()

high_amount = len(
    data[data["amount"] > HIGH_AMOUNT_LIMIT]
)

burst_count = data["reason"].str.contains(
    "Multiple transactions",
    na=False
).sum()

percentage = (
    suspicious / total * 100
    if total > 0 else 0
)


# =====================================
# 6. MAIN HEADER
# =====================================

header_left, header_right = st.columns([2, 1])

with header_left:
    with st.container(border=True):

        st.success("● SYSTEM ACTIVE")

        st.title("🛡️ E-Wallet Security Dashboard")

        st.write(
            "Monitor suspicious transactions, "
            "detect unusual wallet activities "
            "and analyze security events."
        )

        st.caption(
            "Threat Monitoring | CSV Data | Rule-Based Detection"
        )

with header_right:
    with st.container(border=True):

        if suspicious > 0:
            st.error("⚠ Suspicious Activity Found")
        else:
            st.success("✓ No Suspicious Activity")

        st.metric(
            "Activities Requiring Investigation",
            suspicious
        )

        st.progress(int(percentage))

        st.caption(
            f"{percentage:.1f}% suspicious activities"
        )


# =====================================
# 7. SECURITY OVERVIEW
# =====================================

st.write("")
st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    with st.container(border=True):
        st.metric(
            "🚨 Suspicious",
            suspicious,
            delta="Needs investigation",
            delta_color="inverse"
        )

with col2:
    with st.container(border=True):
        st.metric("🟢 Normal", normal)

with col3:
    with st.container(border=True):
        st.metric("↗ Transactions", total)

with col4:
    with st.container(border=True):
        st.metric("👥 Wallets", wallets)


# =====================================
# 8. GENERAL INFORMATION
# =====================================

st.write("")
left, right = st.columns(2)

with left:
    with st.container(border=True):

        st.subheader("📌 General Information")
        st.caption("Data source and analysis metadata")

        st.write("**Data Source**")
        st.info("transactions.csv")

        st.write("**Detection Method**")
        st.info("Rule-Based Detection")

        st.write("**High Amount Threshold**")
        st.info("5,000")

        st.write("**Time Window**")
        st.info("10 Minutes")

with right:
    with st.container(border=True):

        st.subheader("📊 Activity Breakdown")
        st.caption("Observed activities by category")

        st.metric("High Amount Activities", high_amount)
        st.metric("Transaction Burst Activities", burst_count)
        st.metric("Normal Transactions", normal)


# =====================================
# 9. TRANSACTION CHART
# =====================================

st.write("")

with st.container(border=True):

    st.subheader("📈 Transaction Analysis")

    chart_data = (
        data["status"]
        .value_counts()
        .reindex(["Normal", "Suspicious"], fill_value=0)
    )

    st.bar_chart(chart_data, color="#368FFF")


# =====================================
# 10. ADD NEW TRANSACTION
# =====================================

st.write("")

with st.container(border=True):

    st.subheader("➕ Add New Transaction")
    st.caption("Enter transaction information for analysis.")

    with st.form("transaction_form"):

        col1, col2 = st.columns(2)

        with col1:
            wallet_id = st.text_input("Wallet ID")
            amount = st.number_input(
                "Transaction Amount",
                min_value=0.0,
                value=100.0
            )

        with col2:
            merchant = st.text_input("Merchant")
            channel = st.selectbox(
                "Channel",
                ["Mobile", "Web", "POS"]
            )

        submitted = st.form_submit_button(
            "Analyze Transaction",
            use_container_width=True
        )

        if submitted:

            if not wallet_id.strip() or not merchant.strip():
                st.error("Please fill in all fields.")

            else:

                new_row = {
                    "transaction_id": "TX-" + uuid.uuid4().hex[:8],
                    "wallet_id": wallet_id.strip(),
                    "amount": amount,
                    "merchant": merchant.strip(),
                    "channel": channel,
                    "timestamp": pd.Timestamp.now()
                }

                updated_data = pd.concat(
                    [
                        data.drop(columns=["status", "reason"]),
                        pd.DataFrame([new_row])
                    ],
                    ignore_index=True
                )

                updated_data.to_csv(CSV_FILE, index=False)

                st.success("Transaction saved successfully!")
                st.rerun()


# =====================================
# 11. ALL TRANSACTIONS
# =====================================

st.write("")

with st.container(border=True):

    st.subheader("📋 Recent Transactions")

    filter_status = st.selectbox(
        "Filter by Status",
        ["All", "Normal", "Suspicious"]
    )

    if filter_status == "All":
        filtered_data = data
    else:
        filtered_data = data[
            data["status"] == filter_status
        ]

    st.dataframe(
        filtered_data.sort_values(
            "timestamp",
            ascending=False
        ),
        use_container_width=True,
        hide_index=True
    )


# =====================================
# 12. SECURITY ALERTS
# =====================================

st.write("")

with st.container(border=True):

    st.subheader("🚨 Security Alerts")

    alerts = data[
        data["status"] == "Suspicious"
    ]

    if not alerts.empty:

        st.warning(
            f"{len(alerts)} suspicious transactions detected!"
        )

        st.dataframe(
            alerts[
                [
                    "transaction_id",
                    "wallet_id",
                    "amount",
                    "reason"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )

    else:
        st.success("No suspicious activities found.")


# =====================================
# 13. FOOTER
# =====================================

st.divider()

st.caption(
    "E-Wallet Network Threat Detector | "
    "Cybersecurity Educational Project"
)
