"""
guardian_auth.py — Authentication, sessions, and OTP utilities
================================================================
Handles password hashing, session token management, email OTP,
and FastAPI dependency guards (require_login, require_admin).
"""

import bcrypt
import secrets
import smtplib
import json
import os
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import Cookie, HTTPException, Depends, Request
from guardian_db import get_session_by_token, get_user_by_id

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardian_config.json")


# ── Config ─────────────────────────────────────────────────────────────────────
def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_config(cfg):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)

def get_local_api_key() -> str:
    cfg = load_config()
    if "api_key" not in cfg:
        cfg["api_key"] = secrets.token_hex(32)
        save_config(cfg)
    return cfg["api_key"]


# ── Password ───────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


# ── Session Tokens ─────────────────────────────────────────────────────────────
def create_session_token() -> str:
    return secrets.token_urlsafe(32)

def make_expiry(days=7) -> str:
    return (datetime.utcnow() + timedelta(days=days)).isoformat()


# ── OTP ────────────────────────────────────────────────────────────────────────
def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)  # 6-digit

def make_otp_expiry(minutes=10) -> str:
    return (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()


# ── Email ──────────────────────────────────────────────────────────────────────
def send_otp_email(to_email: str, otp_code: str, process_name: str, pid: str):
    cfg = load_config()
    smtp_host = cfg.get("smtp_host", "smtp.gmail.com")
    smtp_port = int(cfg.get("smtp_port", 587))
    smtp_user = cfg.get("smtp_user", "")
    smtp_pass = cfg.get("smtp_password", "")
    from_email = smtp_user

    if not smtp_user or not smtp_pass:
        print(f"[Auth] SMTP not configured. OTP Code for {process_name} (PID {pid}): {otp_code}")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"⚠ Guardian: Whitelist Request — {process_name}"
        msg["From"] = from_email
        msg["To"] = to_email

        text = f"""
Guardian Security Alert
========================
A user has requested to whitelist a process.

Process: {process_name}
PID:     {pid}

Authorization Code: {otp_code}

This code expires in 10 minutes.
If you did not expect this request, ignore this email.
"""
        html = f"""
<div style="font-family: Arial, sans-serif; background:#1e1e2e; color:#e0e0e0; padding:24px; border-radius:12px; max-width:480px;">
  <h2 style="color:#ff4757; margin-top:0;">⚠ Guardian Alert</h2>
  <p>A user has requested whitelist approval for:</p>
  <div style="background:#252535; border-radius:8px; padding:16px; margin:16px 0;">
    <strong>Process:</strong> {process_name}<br>
    <strong>PID:</strong> {pid}
  </div>
  <div style="background:#00ff87; color:#1e1e2e; border-radius:8px; padding:16px; text-align:center; font-size:28px; font-weight:bold; letter-spacing:8px;">
    {otp_code}
  </div>
  <p style="color:#888; font-size:12px; margin-top:16px;">This code expires in 10 minutes. If you did not expect this, ignore this email.</p>
</div>
"""
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, to_email, msg.as_string())

        print(f"[Auth] OTP sent to {to_email} for {process_name}")
        return True
    except Exception as e:
        print(f"[Auth] Email failed: {e}")
        print(f"[Auth] Fallback — OTP Code: {otp_code}")
        return False

def send_auth_otp_email(to_email: str, otp_code: str, purpose: str):
    cfg = load_config()
    smtp_host = cfg.get("smtp_host", "smtp.gmail.com")
    smtp_port = int(cfg.get("smtp_port", 587))
    smtp_user = cfg.get("smtp_user", "")
    smtp_pass = cfg.get("smtp_password", "")
    from_email = smtp_user

    if not smtp_user or not smtp_pass:
        print(f"[Auth] SMTP not configured. {purpose.capitalize()} OTP for {to_email}: {otp_code}")
        return False

    try:
        msg = MIMEMultipart("alternative")
        title = "Email Verification" if purpose == "signup" else "Login Verification"
        msg["Subject"] = f"Guardian: {title}"
        msg["From"] = from_email
        msg["To"] = to_email

        text = f"Your Guardian {title} Code is: {otp_code}\nExpires in 10 minutes."
        html = f"""
        <div style="font-family: Arial, sans-serif; background:#1e1e2e; color:#e0e0e0; padding:24px; border-radius:12px; max-width:480px;">
          <h2 style="color:#00ff87; margin-top:0;">Guardian Security</h2>
          <p>Your {title} Code is:</p>
          <div style="background:#252535; color:#00ff87; border-radius:8px; padding:16px; text-align:center; font-size:32px; font-weight:bold; letter-spacing:8px;">
            {otp_code}
          </div>
          <p style="color:#888; font-size:12px; margin-top:16px;">This code expires in 10 minutes. Do not share it with anyone.</p>
        </div>
        """
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, to_email, msg.as_string())

        print(f"[Auth] Auth OTP sent to {to_email} for {purpose}")
        return True
    except Exception as e:
        print(f"[Auth] Email failed: {e}")
        print(f"[Auth] Fallback — {purpose.capitalize()} OTP Code: {otp_code}")
        return False


# ── FastAPI Guards ────────────────────────────────────────────────────────────
async def get_current_user(guardian_token: str = Cookie(default=None)):
    if not guardian_token:
        return None
    session = await get_session_by_token(guardian_token)
    if not session:
        return None
    return session

async def require_login(guardian_token: str = Cookie(default=None)):
    user = await get_current_user(guardian_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

async def require_admin(guardian_token: str = Cookie(default=None)):
    user = await get_current_user(guardian_token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

async def require_local_api_key(request: Request):
    """Guard for internal machine-to-machine endpoints (e.g. Stop_Guardian, Live Logger)."""
    auth_header = request.headers.get("Authorization")
    expected_key = get_local_api_key()
    
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API Key")
        
    token = auth_header.split(" ")[1]
    if not secrets.compare_digest(token, expected_key):
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return True
