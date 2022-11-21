import json
import sys
import mariadb

'''
QUERIES FROM FILES TABLE
'''

with open('configMariaDB.json', 'r') as f:
    configMariaDB = json.load(f)



def check_file_exists(filename):
    conn = mariadb.connect(**configMariaDB)
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM files WHERE filename= %(filename)s", {
            'filename': filename
        })
    result = cur.fetchone()
    cur.close()
    conn.close()
    if result is None:
        return False
    else:
        return True

def insert_file(filename, user, date_object, hash, size, description):
    conn = mariadb.connect(**configMariaDB)
    cur = conn.cursor()
    inserted = True
    try:
        date = date_object.strftime('%Y-%m-%d %H:%M:%S')
        query = '''
            INSERT INTO files(filename, hash, upload_date, owner, last_modified_by, last_modified_date, size, description)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        '''
        args = (filename, hash, date, user, user, date, size, description)
        cur.execute(query, args)
        conn.commit()
    except mariadb.Error as error:
        inserted = False
    finally:
        cur.close()
        conn.close()
        return inserted

def update_file(filename, user, date_object, hash, size, description):
    conn = mariadb.connect(**configMariaDB)
    cur = conn.cursor()
    updated = True
    try:
        last_modified_date = date_object.strftime('%Y-%m-%d %H:%M:%S')
        query = '''
            UPDATE files
            SET last_modified_by=%s, last_modified_date=%s, hash=%s, size=%s, description=%s
            WHERE filename=%s
        '''
        args = (user, last_modified_date, hash, size, filename, description)
        cur.execute(query, args)
        conn.commit()
    except mariadb.Error as error:
        updated = False
    finally:
        cur.close()
        conn.close()
        return updated

def get_all_files():
    conn = mariadb.connect(**configMariaDB)
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT * FROM files ORDER BY last_modified_date DESC")
    result = cur.fetchall()
    cur.close()
    conn.close()
    return result

def delete_file(filename):
    conn = mariadb.connect(**configMariaDB)
    cur = conn.cursor()
    deleted = True
    try:
        query = '''
            DELETE FROM files
            WHERE filename=%s
        '''
        args = (filename, )
        cur.execute(query, args)
        conn.commit()
    except mariadb.Error as error:
        deleted = False
    finally:
        cur.close()
        conn.close()
        return deleted