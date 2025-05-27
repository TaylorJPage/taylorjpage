import requests
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from matplotlib.animation import FuncAnimation
import matplotlib

# Use a GUI backend for local visualization
matplotlib.use('Qt5Agg')  # Or 'TkAgg' if needed

# Custom User-Agent per API guidelines
HEADERS = {
    'User-Agent': 'osrs-profit-tracker - @TaylorPage on Discord or taylor.jonathan.page@gmail.com'
}

# Your investment portfolio
portfolio = {
    "Contract of shard acquisition": {"qty": 44, "spent": 317792789},
    "Contract of familiar acquisition": {"qty": 2, "spent": 8380222},
    "Contract of oathplate acquisition": {"qty": 1, "spent": 81877777},
    "Contract of bloodied blows": {"qty": 2, "spent": 7200000},
    "Contract of sensory clouding": {"qty": 2, "spent": 6399998},
    "Contract of divine severance": {"qty": 2, "spent": 10867529},
    "Contract of forfeit breath": {"qty": 2, "spent": 12000000},
    "Contract of glyphic attenuation": {"qty": 2, "spent": 8059458},
    "Contract of harmony acquisition": {"qty": 10, "spent": 130841443},
}

# Total amount invested
total_spent = sum(item["spent"] for item in portfolio.values())

# History for plotting
timestamps = []
portfolio_values = []
profit_losses = []

# Get item mapping (names to IDs)
def get_item_mapping():
    try:
        r = requests.get("https://prices.runescape.wiki/api/v1/osrs/mapping", headers=HEADERS)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Error fetching item mapping: {e}")
        return []

# Get latest prices
def get_latest_prices():
    try:
        r = requests.get("https://prices.runescape.wiki/api/v1/osrs/latest", headers=HEADERS)
        r.raise_for_status()
        return r.json().get("data", {})
    except Exception as e:
        print(f"Error fetching latest prices: {e}")
        return {}

# Match item name to ID
def get_item_id(name, mapping):
    for item in mapping:
        if item['name'].lower() == name.lower():
            return item['id']
    return None

# Calculate current total value
def calculate_portfolio_value(mapping, latest_prices):
    total_value = 0
    for name, data in portfolio.items():
        item_id = get_item_id(name, mapping)
        if item_id and str(item_id) in latest_prices:
            price = latest_prices[str(item_id)].get("high") or latest_prices[str(item_id)].get("low")
            if price:
                item_value = price * data["qty"]
                total_value += item_value
                print(f"{name}: Qty={data['qty']}, Price={price:,}, Value={item_value:,}")
            else:
                print(f"{name}: Price data missing, skipping.")
        else:
            print(f"{name}: Missing from latest prices or mapping.")
    return total_value

# Set up the plot
fig, ax = plt.subplots()
plt.tight_layout()

# Update function for animation
def update(frame=None):
    mapping = get_item_mapping()
    latest_prices = get_latest_prices()
    if not mapping or not latest_prices:
        return

    now = datetime.now()
    value = calculate_portfolio_value(mapping, latest_prices)
    profit = value - total_spent

    timestamps.append(now)
    portfolio_values.append(value)
    profit_losses.append(profit)

    ax.clear()
    ax.plot(timestamps, portfolio_values, label="Portfolio Value (GP)", color="green", linewidth=2)
    ax.plot(timestamps, profit_losses, label="Profit/Loss (GP)", color="blue", linestyle="--", linewidth=2)
    ax.set_title("OSRS Investment Tracker")
    ax.set_xlabel("Time")
    ax.set_ylabel("GP")
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax.legend()
    fig.autofmt_xdate()
    plt.tight_layout()

    print(f"[{now.strftime('%H:%M:%S')}] Portfolio Value: {value:,.0f} | Profit/Loss: {profit:,.0f}")

# 🔁 Add initial investment value
initial_time = datetime.now()
timestamps.append(initial_time)
portfolio_values.append(total_spent)
profit_losses.append(0)
print(f"[{initial_time.strftime('%H:%M:%S')}] Starting investment: {total_spent:,} GP")

# 🕒 Start animation (every 60 seconds)
ani = FuncAnimation(fig, update, interval=60000)  # 60,000ms = 1 min

# Launch chart window
print("Launching Profit Tracker UI (updates every 1 minute)...")
plt.show()
