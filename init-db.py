import sqlite3

print('Initializing database...')

db = sqlite3.connect('blomi.db')

cur = db.cursor()
cur.execute('DROP TABLE IF EXISTS hashedBlockInfo')
cur.execute('CREATE TABLE hashedBlockInfo (blockBy TEXT, blockTo TEXT)')
cur.execute('CREATE UNIQUE INDEX hashedBlockInfo_Index ON hashedBlockInfo (blockBy, blockTo)')
cur.close()

db.close()

print('Database initialized.')