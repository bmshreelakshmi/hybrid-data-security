
from google_drive import upload_file

file_path = "test.txt"

with open(file_path, "w", encoding="utf-8") as f:
    f.write("HybridShield Google Drive test")

try:
    result = upload_file(file_path)
    print("Upload successful!")
    print("File name:", result["name"])
    print("Drive file ID:", result["id"])
except Exception as e:
    print("Upload failed:", e)
