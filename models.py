from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()
client = MongoClient(os.getenv("MONGO_URI"))
db = client["mshield"]
collection = db["scans"]

def save_scan_result(data):
    collection.insert_one(data)
