import os
import json 
import hashlib

HASH_TABLE_FILE = "hash_table.json"
CHUNK_SIZE = 8192

def hash_file(file_path: str, algo: str = "sha256" ) -> str:
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def traverse_directory(dir_path: str) -> dict:
    paths = []
    for root, _, files in os.walk(dir_path):
        for name in files:
            paths.append(os.path.abspath(os.path.join(root, name)))
    return paths

def generate_table(dir_path: str, out_file: str = HASH_TABLE_FILE) -> None:
    if not os.path.isdir(dir_path):
        print("Directory does not exist.")
        return
    
    table = {}
    for fp in traverse_directory(dir_path):
        try:
            table[fp] = hash_file(fp)
        except Exception as e:
            print(f"Error hashing  {fp}: {e}")
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(table, f, indent=2)

    print("Hash table generated") 
    print(f"Saved to: {out_file}")
    print(f"Files hashed: {len(table)}")

def validate_hash (dir_path: str, table_file: str = HASH_TABLE_FILE) -> None:
    if not os.path.isfile(table_file):
        print("Hash table file does not exist.")
        return
    
    with open(table_file, "r", encoding="utf-8") as f:
        table = json.load(f)
    
    current_files = set(traverse_directory(dir_path))
    stored_files = set(table.keys())

    for fp in sorted(stored_files - current_files):
        print(f"{fp} -> DELETED")

    for fp in sorted(current_files - stored_files):
        print(f"{fp} -> NEW FILE ADDED")

    for fp in sorted(stored_files & current_files):
        try:
            current_hash = hash_file(fp)
            if current_hash == table[fp]:
                print(f"{fp} hash is valid")
            else:
                print(f"{fp} hash is INVALID")
        except Exception as e:
            print(f"ERROR validating: {e}")

def main():
    print("1) Generate new hash table")
    print("2) Verify hashes")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        dir_path = input("Enter directory path to hash: ").strip()
        out_name = input(f"Output json filename (press Enter for {HASH_TABLE_FILE}): ").strip()
        if not out_name:
            out_name = HASH_TABLE_FILE
        generate_table(dir_path, out_name)
        
    elif choice == "2":
        dir_path = input("Enter directory path to verify: ").strip()
        table_name = input(f"Hash table filename (press Enter for {HASH_TABLE_FILE}): ").strip()
        if not table_name:
            table_name = HASH_TABLE_FILE
        validate_hash(dir_path, table_name)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()