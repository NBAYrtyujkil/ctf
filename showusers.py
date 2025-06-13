import sqlite3
import os

# تحديد مسار قاعدة البيانات
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, 'ctf.db')

# الاتصال بقاعدة البيانات
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# جلب جميع المستخدمين والنقاط
cur.execute("SELECT id, username, score FROM users")
rows = cur.fetchall()

print("📋 قائمة المستخدمين:")
for row in rows:
    print(f"🧑 ID: {row[0]} | Username: {row[1]} | Score: {row[2]}")

conn.close()
