import sqlite3
import psycopg2

#conn = sqlite3.connect('users.db')
conn = psycopg2.connect(
    database="postgres", user='myuser', password='mypass', host='127.0.0.1', port='5432'
)

mod = 0
cursor = conn.cursor()

if mod == 0:
    cursor.execute('SELECT * FROM users')
    for a in cursor.fetchall():
        print(a)
    print("---------------------------------------------")
    cursor.execute('SELECT * FROM onlineUsers')
    # cursor.execute('PRAGMA table_info(onlineUsers);')

    for a in cursor.fetchall():
        print(a)
    print("----------------------------------------------------")

else:
    cursor.execute('DROP TABLE users')
    conn.commit()
    cursor.execute('DROP TABLE onlineUsers')

conn.commit()

"""
connection = sqlite3.connect('users.db')
cursor = connection.execute('select * from onlineUsers')
names = list(map(lambda x: x[0], cursor.description))
connection.close()
print(names)
"""