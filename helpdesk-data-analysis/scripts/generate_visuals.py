import pandas as pd
import matplotlib.pyplot as plt
import os

# Load data
import os
script_dir = os.path.dirname(__file__)
csv_path = os.path.join(script_dir, '..', 'data', 'tickets.csv')
df = pd.read_csv(csv_path, parse_dates=['submitted_at', 'resolved_at'])
df['resolution_time'] = (df['resolved_at'] - df['submitted_at']).dt.total_seconds() / 3600

# Make output folder
visuals_path = os.path.join(script_dir, '..', 'visuals')

os.makedirs(visuals_path, exist_ok=True)

# Tickets by category
category_counts = df['category'].value_counts()
category_counts.plot(kind='bar', title='Tickets by Category', color='skyblue')
plt.tight_layout()
plt.savefig(os.path.join(visuals_path, 'tickets_by_category.png'))
print(f"Saving tickets_by_category to: {os.path.join(visuals_path, 'tickets_by_category.png')}")
plt.close()

# Avg resolution time by tech
avg_time = df.groupby('assigned_to')['resolution_time'].mean()
avg_time.plot(kind='bar', title='Avg Resolution Time by Technician (Hours)', color='coral')
plt.tight_layout()
plt.savefig(os.path.join(visuals_path, 'avg_resolution_time.png'))
print(f"Saving avg_resolution_time to: {os.path.join(visuals_path, 'avg_resolution_time.png')}")
print("Chart saved.")
plt.close()


