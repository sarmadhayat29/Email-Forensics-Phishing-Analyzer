import os
import sys
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# File Paths
UPLOAD_DIR = os.path.join(BASE_DIR, "server_uploads")
REPORTS_DIR = os.path.join(BASE_DIR, "server_reports")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("FATAL: DATABASE_URL environment variable is not set.", file=sys.stderr)
    sys.exit(1)

if "[YOUR-PASSWORD]" in DATABASE_URL or "[YOUR-PROJECT-REF]" in DATABASE_URL:
    print("\n" + "="*60, file=sys.stderr)
    print("FATAL: Your .env file still contains placeholder values!", file=sys.stderr)
    print("Please open the .env file and replace [YOUR-PASSWORD] and [YOUR-PROJECT-REF]", file=sys.stderr)
    print("with your actual Supabase credentials.", file=sys.stderr)
    print("="*60 + "\n", file=sys.stderr)
    sys.exit(1)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    print("FATAL: JWT_SECRET environment variable is not set.", file=sys.stderr)
    sys.exit(1)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7

# Security & CORS Configuration
ALLOWED_ORIGINS_ENV = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:8000,http://localhost:8000")
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_ENV.split(",") if origin.strip()]

# Application Configuration
MAX_UPLOAD_SIZE = 15 * 1024 * 1024  # 15 MB
