
import os
import json
import hashlib
from typing import Dict, Tuple

DEFAULT_ALGO = "sha256"
DEFAULT_TABLE_NAME = "hash_table.json"


def hash_file(filepath: str, algo: str = DEFAULT_ALGO, chunk_size: int = 1024 * 1024) -> str:
    """Return cryptographic hash of a file."""
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def traverse_directory(root_dir: str) -> Dict[str, str]:
    """Hash all files in a directory and return {relative_path: hash}."""
    if not os.path.isdir(root_dir):
        raise ValueError(f"Not a directory: {root_dir}")

    table: Dict[str, str] = {}

    for dirpath, _, filenames in os.walk(root_dir):
        for name in filenames:
            full_path = os.path.join(dirpath, name)

            if os.path.abspath(full_path) == os.path.abspath(
                os.path.join(root_dir, DEFAULT_TABLE_NAME)
            ):
                continue

            rel_path = os.path.relpath(full_path, root_dir)

            try:
                table[rel_path] = hash_file(full_path)
            except (PermissionError, FileNotFoundError) as e:
                table[rel_path] = f"ERROR: {type(e).__name__}"

    return table


def generate_table(root_dir: str, output_json: str = DEFAULT_TABLE_NAME) -> None:
    """Generate JSON hash table for directory."""
    hashes = traverse_directory(root_dir)

    payload = {
        "base_directory": os.path.abspath(root_dir),
        "algorithm": DEFAULT_ALGO,
        "files": hashes
    }

    out_path = os.path.join(root_dir, output_json)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)

    print(f"Hash table generated: {out_path}")


def load_table(json_path: str) -> Tuple[str, str, Dict[str, str]]:
    """Load hash table JSON."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "base_directory" not in data or "algorithm" not in data or "files" not in data:
        raise ValueError("Invalid hash table JSON format.")

    return data["base_directory"], data["algorithm"], data["files"]


def validate_hash(table_json_path: str) -> None:
    """Verify current files against stored hashes."""
    base_dir, algo, stored_files = load_table(table_json_path)

    if not os.path.isdir(base_dir):
        print(f"Base directory missing: {base_dir}")
        return

    current_files = traverse_directory(base_dir)

    stored_set = set(stored_files.keys())
    current_set = set(current_files.keys())

    for rel_path in sorted(stored_set - current_set):
        print(f"File deleted: {rel_path}")

    for rel_path in sorted(current_set - stored_set):
        print(f"New file added: {rel_path}")

    for rel_path in sorted(stored_set & current_set):
        stored_hash = stored_files.get(rel_path)
        current_hash = current_files.get(rel_path)

        if stored_hash == current_hash:
            print(f"{rel_path} hash is valid")
        else:
            print(f"{rel_path} hash is invalid")


def main() -> None:
    print("Hash Demonstration Program")
    print("1) Generate hash table")
    print("2) Verify hashes")

    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        directory = input("Enter directory path: ").strip()
        try:
            generate_table(directory)
        except Exception as e:
            print(f"Error: {e}")

    elif choice == "2":
        table_path = input("Enter path to hash_table.json: ").strip()
        try:
            validate_hash(table_path)
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()
