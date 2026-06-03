# @helper_man Number Info API

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Create your `.env` file:
   ```
   cp .env.example .env
   ```
   Then open `.env` and set your admin username and password.

3. Run the server:
   ```
   uvicorn main:app --reload
   ```

## Access

- **API:** `http://localhost:8000/api/number-info?number=7439312179&apikey=YOUR_KEY`
- **Admin Panel:** `http://localhost:8000/admin`
  - Login with the username/password you set in `.env`

## Admin Panel Features
- Generate API keys with custom labels, request limits, and expiry
- Enable / Disable keys
- Delete keys
- View per-key usage and request logs
- Dashboard with live stats

## .env Variables
```
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password_here
```
