#!/usr/bin/env python3
"""
seed_data.py — Generate sample login history in MongoDB for demo purposes.
Run: python seed_data.py
Requires: pymongo (pip install pymongo)
"""

import random
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import MongoClient

MONGO_URI = 'mongodb://localhost:27017/sentinel_zero'
client = MongoClient(MONGO_URI)
db = client['sentinel_zero']

# Clear existing data
db.loginevents.drop()
print('✅ Cleared existing login events')

# Sample user IDs (replace with real ones after signing up)
USERS = [
    {'id': ObjectId('000000000000000000000001'), 'username': 'alice'},
    {'id': ObjectId('000000000000000000000002'), 'username': 'bob'},
]

AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537',
    'Mozilla/5.0 (Linux; Android 11) Mobile Chrome/118',
]

events = []

for user in USERS:
    # Generate 30 normal logins (weekdays 8–18h, known device)
    for _ in range(30):
        dt = datetime.now() - timedelta(days=random.randint(1, 60))
        hour = random.randint(8, 18)
        dt = dt.replace(hour=hour, minute=random.randint(0, 59))
        events.append({
            'userId': user['id'],
            'username': user['username'],
            'ipAddress': f'192.168.1.{random.randint(1, 10)}',
            'userAgent': AGENTS[0],  # always same device
            'loginHour': hour,
            # (weekday()+1)%7 maps Mon=1..Sat=6, Sun=0 — matches JS getDay()
            'loginDayOfWeek': (dt.weekday() + 1) % 7,
            'anomalyScore': random.uniform(-0.1, 0.1),
            'riskScore': random.randint(0, 20),
            'riskLevel': 'low',
            'isAnomaly': False,
            'action': 'allow',
            'status': 'success',
            'createdAt': dt,
            'updatedAt': dt,
        })

    # Generate 5 anomalous logins (midnight, unknown device)
    for _ in range(5):
        dt = datetime.now() - timedelta(days=random.randint(1, 10))
        hour = random.randint(0, 4)
        dt = dt.replace(hour=hour)
        risk = random.randint(70, 100)
        events.append({
            'userId': user['id'],
            'username': user['username'],
            'ipAddress': f'10.20.30.{random.randint(1, 255)}',
            'userAgent': AGENTS[2],  # mobile — new device
            'loginHour': hour,
            # (weekday()+1)%7 maps Mon=1..Sat=6, Sun=0 — matches JS getDay()
            'loginDayOfWeek': (dt.weekday() + 1) % 7,
            'isNewDevice': True,
            'anomalyScore': random.uniform(-0.5, -0.2),
            'riskScore': risk,
            'riskLevel': 'high' if risk >= 70 else 'medium',
            'isAnomaly': True,
            'action': 'terminate_session',
            'status': 'success',
            'createdAt': dt,
            'updatedAt': dt,
        })

result = db.loginevents.insert_many(events)
print(f'✅ Inserted {len(result.inserted_ids)} login events')
print('🎉 Seed complete! Open the dashboard to see the data.')
