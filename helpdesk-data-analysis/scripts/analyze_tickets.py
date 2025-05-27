import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('data/tickets.csv', parse_dates=['submitted_at', 'resolved_at'])
df['resolution_time'] = (df['resolved_at'] - df['submitted_at']).dt.total_seconds() / 3600

# Tickets per category
df['category'].value_counts().plot(kind='bar', title='Tickets by Category')
plt.tight_layout()
plt.savefig('tickets_by_category.png')

# Avg resolution time by tech
avg_time = df.groupby('assigned_to')['resolution_time'].mean()
avg_time.plot(kind='bar', title='Average Resolution Time by Technician')
plt.tight_layout()
plt.savefig('avg_resolution_time.png')
