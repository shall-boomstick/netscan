#!/usr/bin/env python3
"""
Database migration script for NetScan

This script adds the missing authentication columns to the existing database.
"""

import sqlite3
import os
from datetime import datetime

def migrate_database():
    """Migrate the database to add authentication columns"""
    
    db_path = "netscan.db"
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found. Creating new database...")
        return
    
    print(f"Migrating database: {db_path}")
    
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if the new columns already exist
        cursor.execute("PRAGMA table_info(hosts)")
        columns = [column[1] for column in cursor.fetchall()]
        
        print(f"Existing columns: {columns}")
        
        # Add missing columns if they don't exist
        if 'working_username' not in columns:
            print("Adding working_username column...")
            cursor.execute("ALTER TABLE hosts ADD COLUMN working_username VARCHAR(100)")
        
        if 'auth_method' not in columns:
            print("Adding auth_method column...")
            cursor.execute("ALTER TABLE hosts ADD COLUMN auth_method VARCHAR(50)")
        
        if 'auth_attempts' not in columns:
            print("Adding auth_attempts column...")
            cursor.execute("ALTER TABLE hosts ADD COLUMN auth_attempts INTEGER")
        
        # Commit the changes
        conn.commit()
        print("Database migration completed successfully!")
        
        # Verify the migration
        cursor.execute("PRAGMA table_info(hosts)")
        new_columns = [column[1] for column in cursor.fetchall()]
        print(f"Updated columns: {new_columns}")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database() 