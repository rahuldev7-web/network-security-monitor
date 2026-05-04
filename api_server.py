import uvicorn
from detector import app

if __name__ == "__main__":
    print("\n[*] Starting Network Security Monitor API Server...")
    print("[*] API docs: http://localhost:8000/docs")
    print("[*] Health: http://localhost:8000/health\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)