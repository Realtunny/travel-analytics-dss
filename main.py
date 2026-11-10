"""
Travel Analytics System - v4.0 (JWT + TOTP 2FA Authentication)
"""

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import os
from datetime import datetime, timedelta
import traceback
import secrets
import hashlib
import pyotp
from jose import JWTError, jwt
import qrcode
import io
import base64

app = FastAPI(title="Travel Analytics System", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# CONFIGURATION — CHANGE THESE IN PRODUCTION
# ============================================================
DB_CONFIG = {
    "host": "#",
    "database": "#",
    "user": "#",
    "password": "#",
    "port": "#"
}

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
TOTP_ISSUER_NAME = "Travel Analytics"

# ============================================================
# DATABASE CONNECTION
# ============================================================
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

# ============================================================
# PASSWORD UTILITIES
# ============================================================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain: str, stored: str) -> bool:
    if stored == plain:
        return True
    return stored == hash_password(plain)

# ============================================================
# JWT UTILITIES
# ============================================================
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    token_jti = secrets.token_urlsafe(32)
    to_encode.update({"exp": expire, "type": "refresh", "jti": token_jti})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM), token_jti

def verify_token(token: str, token_type: str = "access"):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != token_type:
            return None
        return payload
    except JWTError:
        return None

# ============================================================
# TOTP UTILITIES
# ============================================================
def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str, issuer: str = TOTP_ISSUER_NAME):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

def verify_totp_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=2)

def generate_qr_base64(uri: str) -> str:
    """Generate QR code as base64 PNG data URI."""
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

# ============================================================
# AUDIT LOGGING
# ============================================================
def log_audit(user_id: int, action: str, ip_address: str, user_agent: str):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO login_audit (user_id, action, ip_address, user_agent) VALUES (%s, %s, %s, %s)",
            (user_id, action, ip_address, user_agent)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass  # Don't fail login if audit logging fails

# ============================================================
# AUTH DEPENDENCY
# ============================================================
async def get_current_user(request: Request):
    """Extract and verify JWT from cookie or Authorization header."""
    token = request.cookies.get("access_token")

    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = verify_token(token, "access")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = int(payload["sub"])

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "SELECT user_id, email, full_name, department, is_active, is_2fa_enabled, role FROM users WHERE user_id = %s",
        (user_id,)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not user["is_active"]:
        raise HTTPException(status_code=403, detail="User not found or deactivated")

    return user


# ============================================================
# AUTH HELPER FOR HTML PAGES (redirects instead of JSON error)
# ============================================================
async def get_user_or_none(request: Request):
    """Try to get current user. Returns None if not authenticated (for HTML routes)."""
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        return None
    payload = verify_token(token, "access")
    if not payload:
        return None
    user_id = int(payload["sub"])
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT user_id, email, full_name, department, is_active, is_2fa_enabled, role FROM users WHERE user_id = %s",
            (user_id,)
        )
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not user or not user["is_active"]:
            return None
        return user
    except Exception:
        return None

async def require_admin(user: dict = Depends(get_current_user)):
    """Dependency that ensures the user is an admin."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ============================================================
# TOKEN ISSUANCE HELPER
# ============================================================
async def issue_tokens(response: Response, user: dict, request: Request = None):
    """Issue access + refresh tokens and set HttpOnly cookies."""
    access_token = create_access_token({
        "sub": str(user["user_id"]),
        "email": user["email"],
        "name": user["full_name"]
    })
    refresh_token, token_jti = create_refresh_token({"sub": str(user["user_id"])})

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("user-agent") if request else None

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent) VALUES (%s, %s, %s, %s, %s)",
        (user["user_id"], token_hash, datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), ip_address, user_agent)
    )
    cur.execute("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE user_id = %s", (user["user_id"],))
    conn.commit()
    cur.close()
    conn.close()

    response.set_cookie(
        key="access_token", value=access_token, httponly=True,
        secure=False, samesite="lax", max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token, httponly=True,
        secure=False, samesite="lax", max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/"
    )

    return {"success": True, "user": user["full_name"], "requires_2fa": False}

# ============================================================
# Pydantic Models
# ============================================================
class LoginStep1Request(BaseModel):
    email: str
    password: str

class LoginStep2Request(BaseModel):
    email: str
    temp_token: str
    totp_code: str

class RefreshRequest(BaseModel):
    refresh_token: str = None

# ============================================================
# ============================================================
# REGISTRATION PAGE HTML
# ============================================================
REGISTER_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Travel Analytics — Register</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .register-box {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 460px;
            width: 100%;
            box-shadow: 0 25px 70px rgba(0,0,0,0.35);
            text-align: center;
        }
        .logo {
            width: 60px; height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 16px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
            margin-bottom: 16px;
        }
        h1 { font-size: 22px; color: #333; margin-bottom: 6px; }
        .subtitle { color: #888; font-size: 13px; margin-bottom: 24px; }
        .form-group { text-align: left; margin-bottom: 16px; }
        label { display: block; font-size: 12px; font-weight: 600; color: #555; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 0.5px; }
        input[type="text"], input[type="email"], input[type="password"], select {
            width: 100%; padding: 12px 14px;
            border: 2px solid #e8e8e8; border-radius: 10px;
            font-size: 14px; transition: all 0.2s;
        }
        input:focus, select:focus { outline: none; border-color: #667eea; }
        .btn {
            width: 100%; padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; border-radius: 10px;
            font-size: 15px; font-weight: 600; cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(102,126,234,0.4); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        .status {
            margin-top: 15px; padding: 12px; border-radius: 8px;
            font-size: 13px; display: none;
        }
        .status.error { background: #fde8e8; color: #c53030; display: block; }
        .status.loading { background: #fff3cd; color: #856404; display: block; }
        .status.success { background: #d4edda; color: #155724; display: block; }
        .footer { margin-top: 20px; font-size: 13px; color: #666; }
        .footer a { color: #667eea; text-decoration: none; font-weight: 600; }
        .footer a:hover { text-decoration: underline; }
        .password-strength { height: 4px; border-radius: 2px; margin-top: 6px; transition: all 0.3s; }
        .strength-weak { background: #ef4444; width: 33%; }
        .strength-medium { background: #f59e0b; width: 66%; }
        .strength-strong { background: #10b981; width: 100%; }
    </style>
</head>
<body>
    <div class="register-box">
        <div class="logo">&#128100;</div>
        <h1>Create Account</h1>
        <p class="subtitle">Register to access the Travel Analytics portal</p>
        <form id="registerForm">
            <div class="form-group">
                <label>Full Name</label>
                <input type="text" id="fullName" placeholder="John Doe" required autofocus>
            </div>
            <div class="form-group">
                <label>Email Address</label>
                <input type="email" id="email" placeholder="you@company.com" required>
            </div>
<!--DEPT FIELD COMMENTED OUT
            <div class="form-group">
                <label>Department</label>
                <select id="department" required>
                    <option value="">Select Department</option>
                    <option value="IT">IT</option>
                    <option value="Sales">Sales</option>
                    <option value="Operations">Operations</option>
                    <option value="Finance">Finance</option>
                    <option value="Admin">Admin</option>
                    <option value="Protocol">Protocol</option>
                </select>
            </div>
END DEPT FIELD-->
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="password" placeholder="Min 6 characters" required minlength="6">
                <div class="password-strength" id="pwdStrength"></div>
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" id="confirmPassword" placeholder="Re-enter password" required>
            </div>
            <button type="submit" class="btn" id="registerBtn">Create Account</button>
            <div id="status" class="status"></div>
        </form>
        <p class="footer">Already have an account? <a href="/login">Sign In</a></p>
    </div>
    <script>
        document.getElementById("password").addEventListener("input", (e) => {
            const val = e.target.value;
            const bar = document.getElementById("pwdStrength");
            bar.className = "password-strength";
            if (val.length >= 8 && /[A-Z]/.test(val) && /[0-9]/.test(val)) {
                bar.classList.add("strength-strong");
            } else if (val.length >= 6) {
                bar.classList.add("strength-medium");
            } else if (val.length > 0) {
                bar.classList.add("strength-weak");
            }
        });

        document.getElementById("registerForm").addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("registerBtn");
            const status = document.getElementById("status");
            const password = document.getElementById("password").value;
            const confirm = document.getElementById("confirmPassword").value;

            if (password !== confirm) {
                status.className = "status error";
                status.textContent = "Passwords do not match.";
                return;
            }
            if (password.length < 6) {
                status.className = "status error";
                status.textContent = "Password must be at least 6 characters.";
                return;
            }

            btn.disabled = true;
            status.className = "status loading";
            status.textContent = "Creating account...";

            const data = {
                full_name: document.getElementById("fullName").value.trim(),
                email: document.getElementById("email").value.trim().toLowerCase(),
                //department: document.getElementById("department").value,
                password: password
            };

            try {
                const res = await fetch("/api/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(data)
                });
                const result = await res.json();
                if (res.ok && result.success) {
                    status.className = "status success";
                    status.innerHTML = "<b>Account created successfully!</b><br>Redirecting to login...";
                    setTimeout(() => window.location.href = "/login", 1500);
                } else {
                    status.className = "status error";
                    status.textContent = result.detail || "Registration failed.";
                    btn.disabled = false;
                }
            } catch (err) {
                status.className = "status error";
                status.textContent = "Network error. Please try again.";
                btn.disabled = false;
            }
        });
    </script>
</body>
</html>
"""

# LOGIN PAGE HTML (Two-Step)
# ============================================================
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Travel Analytics — Login v4.0</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .login-box {
            background: white;
            border-radius: 20px;
            padding: 45px 40px;
            max-width: 420px;
            width: 100%;
            box-shadow: 0 25px 70px rgba(0,0,0,0.35);
            text-align: center;
        }
        .logo {
            width: 70px; height: 70px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 18px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 28px;
            margin-bottom: 18px;
        }
        h1 { font-size: 22px; color: #333; margin-bottom: 6px; }
        .subtitle { color: #888; font-size: 13px; margin-bottom: 28px; }
        .form-group { text-align: left; margin-bottom: 18px; }
        label { display: block; font-size: 12px; font-weight: 600; color: #555; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
        input[type="email"], input[type="password"], input[type="text"] {
            width: 100%; padding: 13px 15px;
            border: 2px solid #e8e8e8; border-radius: 10px;
            font-size: 14px; transition: all 0.2s;
        }
        input:focus { outline: none; border-color: #667eea; }
        .btn {
            width: 100%; padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; border-radius: 10px;
            font-size: 15px; font-weight: 600; cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 8px 20px rgba(102,126,234,0.4); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        .status {
            margin-top: 15px; padding: 12px; border-radius: 8px;
            font-size: 13px; display: none;
        }
        .status.error { background: #fde8e8; color: #c53030; display: block; }
        .status.loading { background: #fff3cd; color: #856404; display: block; }
        .status.success { background: #d4edda; color: #155724; display: block; }
        .footer { margin-top: 22px; font-size: 11px; color: #aaa; }
        .totp-hint { font-size: 11px; color: #888; margin-top: 4px; }
        .step-indicator { font-size: 12px; color: #667eea; font-weight: 600; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">&#128274;</div>
        <h1>Travel Analytics</h1>
        <p class="subtitle">Sign in to access the upload portal</p>
        <div class="step-indicator" id="stepIndicator">Step 1 of 2: Enter your credentials</div>
        <form id="loginForm">
            <div class="form-group" id="emailGroup">
                <label>Email Address</label>
                <input type="email" id="email" placeholder="you@company.com" required autofocus>
            </div>
            <div class="form-group" id="passwordGroup">
                <label>Password</label>
                <input type="password" id="password" placeholder="Enter your password" required>
            </div>
            <div class="form-group" id="totpGroup" style="display:none;">
                <label>Authenticator Code</label>
                <input type="text" id="totpCode" placeholder="000000" maxlength="6" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code">
                <p class="totp-hint">Enter the 6-digit code from your authenticator app</p>
            </div>
            <button type="submit" class="btn" id="loginBtn">Sign In</button>
            <div id="status" class="status"></div>
        </form>
        <p class="footer">Travel Analytics System | Secured with 2FA<br><a href="/register" style="color:#667eea;text-decoration:none;font-weight:600;">Create Account</a></p>
    </div>
    <script>
        let step = 1;
        let tempToken = null;

        document.getElementById("loginForm").addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("loginBtn");
            const status = document.getElementById("status");
            btn.disabled = true;
            status.className = "status loading";
            status.textContent = step === 1 ? "Verifying credentials..." : "Verifying 2FA code...";
            status.style.display = "block";

            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value;
            const totpCode = document.getElementById("totpCode").value;

            console.log("[FRONTEND] Step:", step, "Email:", email);

            try {
                let res, data;

                if (step === 1) {
                    console.log("[FRONTEND] Calling /api/login/step1");
                    res = await fetch("/api/login/step1", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ email, password })
                    });
                    data = await res.json();
                    console.log("[FRONTEND] Step1 response:", data);

                    if (res.ok && data.requires_2fa) {
                        console.log("[FRONTEND] 2FA REQUIRED! Switching to step 2.");
                        tempToken = data.temp_token;
                        step = 2;
                        document.getElementById("stepIndicator").textContent = "Step 2 of 2: Two-Factor Authentication";
                        document.getElementById("passwordGroup").style.display = "none";
                        document.getElementById("totpGroup").style.display = "block";
                        document.getElementById("loginBtn").textContent = "Verify & Sign In";
                        document.getElementById("totpCode").focus();
                        status.className = "status";
                        status.style.display = "none";
                        btn.disabled = false;
                        return;
                    } else {
                        console.log("[FRONTEND] 2FA NOT required. requires_2fa=", data.requires_2fa);
                    }
                } else {
                    console.log("[FRONTEND] Calling /api/login/step2 with temp_token and totp_code");
                    res = await fetch("/api/login/step2", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ email, temp_token: tempToken, totp_code: totpCode })
                    });
                    data = await res.json();
                    console.log("[FRONTEND] Step2 response:", data);
                }

                if (res.ok && data.success) {
                    console.log("[FRONTEND] Login successful! Redirecting to /");
                    window.location.href = "/";
                } else {
                    console.log("[FRONTEND] Login failed:", data);
                    status.className = "status error";
                    status.textContent = data.detail || "Login failed.";
                    status.style.display = "block";
                    btn.disabled = false;
                }
            } catch (err) {
                console.error("[FRONTEND] Error:", err);
                status.className = "status error";
                status.textContent = "Network error. Please try again.";
                status.style.display = "block";
                btn.disabled = false;
            }
        });
    </script>
</body>
</html>
"""

# ============================================================
# 2FA SETUP PAGE HTML
# ============================================================
SETUP_2FA_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Travel Analytics — Setup 2FA</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .box {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 25px 70px rgba(0,0,0,0.35);
            text-align: center;
        }
        h1 { font-size: 20px; color: #333; margin-bottom: 8px; }
        .subtitle { color: #888; font-size: 13px; margin-bottom: 25px; }
        .qr-box {
            background: #f8f9ff;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .qr-box img { max-width: 200px; border-radius: 8px; }
        .secret-box {
            background: #fff3cd;
            border: 1px dashed #ffc107;
            border-radius: 8px;
            padding: 10px;
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
            margin-bottom: 20px;
            color: #856404;
        }
        .form-group { text-align: left; margin-bottom: 18px; }
        label { display: block; font-size: 12px; font-weight: 600; color: #555; margin-bottom: 6px; }
        input[type="text"] {
            width: 100%; padding: 13px 15px;
            border: 2px solid #e8e8e8; border-radius: 10px;
            font-size: 14px; text-align: center; letter-spacing: 4px;
        }
        input:focus { outline: none; border-color: #667eea; }
        .btn {
            width: 100%; padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; border-radius: 10px;
            font-size: 15px; font-weight: 600; cursor: pointer;
        }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .status { margin-top: 15px; padding: 12px; border-radius: 8px; font-size: 13px; display: none; }
        .status.error { background: #fde8e8; color: #c53030; display: block; }
        .status.success { background: #d4edda; color: #155724; display: block; }
        .status.loading { background: #fff3cd; color: #856404; display: block; }
        ol { text-align: left; font-size: 13px; color: #555; margin: 0 0 20px 20px; }
        ol li { margin-bottom: 6px; }
    </style>
</head>
<body>
    <div class="box">
        <h1>&#128272; Setup Two-Factor Authentication</h1>
        <p class="subtitle">Secure your account with an authenticator app</p>
        <ol>
            <li>Download <b>Google Authenticator</b> or <b>Microsoft Authenticator</b></li>
            <li>Scan the QR code below</li>
            <li>Enter the 6-digit code to verify</li>
        </ol>
        <div class="qr-box">
            <img id="qrImage" src="" alt="Scan with Authenticator">
        </div>
        <p style="font-size:12px;color:#888;margin-bottom:8px;">Or enter this key manually:</p>
        <div class="secret-box" id="secretText"></div>
        <form id="verifyForm">
            <div class="form-group">
                <label>Verification Code</label>
                <input type="text" id="verifyCode" placeholder="000000" maxlength="6" inputmode="numeric" required>
            </div>
            <input type="hidden" id="secretValue">
            <button type="submit" class="btn" id="verifyBtn">Enable 2FA</button>
            <div id="status" class="status"></div>
        </form>
        <p style="margin-top:15px;font-size:12px;"><a href="/" style="color:#667eea;text-decoration:none;">&#8592; Back to Dashboard</a></p>
    </div>
    <script>
        // Fetch setup data on load
        (async () => {
            try {
                const res = await fetch("/api/2fa/setup", { method: "POST" });
                const data = await res.json();
                if (res.ok) {
                    document.getElementById("qrImage").src = data.qr_base64;
                    document.getElementById("secretText").textContent = data.secret;
                    document.getElementById("secretValue").value = data.secret;
                } else {
                    document.getElementById("status").className = "status error";
                    document.getElementById("status").textContent = data.detail || "Failed to load setup.";
                }
            } catch (e) {
                document.getElementById("status").className = "status error";
                document.getElementById("status").textContent = "Network error.";
            }
        })();

        document.getElementById("verifyForm").addEventListener("submit", async (e) => {
            e.preventDefault();
            const btn = document.getElementById("verifyBtn");
            const status = document.getElementById("status");
            btn.disabled = true;
            status.className = "status loading";
            status.textContent = "Verifying...";

            const code = document.getElementById("verifyCode").value;
            const secret = document.getElementById("secretValue").value;

            const formData = new FormData();
            formData.append("code", code);
            formData.append("secret", secret);

            try {
                const res = await fetch("/api/2fa/verify-and-enable", { method: "POST", body: formData });
                const data = await res.json();
                if (res.ok && data.success) {
                    status.className = "status success";
                    status.innerHTML = "<b>2FA Enabled Successfully!</b><br>You'll now need your authenticator code every time you log in.<br><a href='/' style='color:#155724;font-weight:600;'>Go to Dashboard &rarr;</a>";
                } else {
                    status.className = "status error";
                    status.textContent = data.detail || "Invalid code.";
                    btn.disabled = false;
                }
            } catch (e) {
                status.className = "status error";
                status.textContent = "Network error.";
                btn.disabled = false;
            }
        });
    </script>
</body>
</html>
"""

# ============================================================
# UPLOAD PAGE HTML
# ============================================================
UPLOAD_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Travel Analytics - Upload</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            padding: 30px 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 35px;
            max-width: 700px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        h1 { color: #333; font-size: 24px; }
        .user-info { font-size: 12px; color: #666; text-align: right; }
        .user-info strong { color: #667eea; }
        .logout-btn {
            background: #f8f9fa; color: #667eea; border: 1px solid #e2e8f0;
            padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer;
            font-weight: 600; margin-top: 4px;
        }
        .logout-btn:hover { background: #667eea; color: white; }
        .subtitle { color: #666; margin-bottom: 20px; font-size: 13px; }
        .type-selector { display: flex; gap: 10px; margin-bottom: 20px; justify-content: center; }
        .type-btn {
            padding: 12px 24px; border: 2px solid #667eea; background: white;
            color: #667eea; border-radius: 25px; cursor: pointer;
            font-weight: 600; transition: all 0.3s; font-size: 14px;
        }
        .type-btn:hover { background: #f0f4ff; }
        .type-btn.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border-color: transparent;
        }
        .upload-area {
            border: 3px dashed #667eea; border-radius: 15px; padding: 40px;
            text-align: center; margin-bottom: 15px; transition: all 0.3s;
            cursor: pointer; background: #fafbff;
        }
        .upload-area:hover { background: #f0f4ff; border-color: #764ba2; }
        input[type="file"] { display: none; }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 15px 40px;
            border-radius: 30px; font-size: 16px; cursor: pointer;
            width: 100%; font-weight: 600; transition: transform 0.2s;
        }
        .btn:hover { transform: translateY(-2px); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        .status { margin-top: 15px; padding: 15px; border-radius: 10px; display: none; font-size: 13px; }
        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; display: block; }
        .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; display: block; }
        .status.loading { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; display: block; }
        .preview-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 11px; }
        .preview-table th, .preview-table td { border: 1px solid #ddd; padding: 6px; text-align: left; }
        .preview-table th { background: #667eea; color: white; }
        .preview-table tr:nth-child(even) { background: #f8f9ff; }
        .stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-top: 15px; }
        .stat-card { background: #f8f9ff; padding: 12px; border-radius: 8px; text-align: center; }
        .stat-card .number { font-size: 20px; font-weight: bold; color: #667eea; }
        .stat-card .label { font-size: 11px; color: #666; margin-top: 3px; }
        .info-box {
            background: #f0f4ff; padding: 15px; border-radius: 10px;
            margin-bottom: 20px; font-size: 13px; color: #444;
        }
        .info-box h3 { margin-bottom: 8px; color: #667eea; font-size: 14px; }
        .info-box ul { margin-left: 18px; }
        .info-box li { margin-bottom: 3px; font-size: 12px; }
        .security-badge {
            display: inline-block; background: #d1fae5; color: #065f46;
            padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Travel Analytics System</h1>
                <p class="subtitle">Upload Ticket, Hotel, or Ancillary CSV file</p>
            </div>
            <div class="user-info">
                <div>Signed in as <strong>__USER_NAME__</strong> <span class="security-badge">&#128272; 2FA</span></div>
                <a href="/history" style="font-size:11px;color:#667eea;text-decoration:none;font-weight:600;margin-right:8px;">&#128220; History</a>
                <a href="/setup-2fa" style="font-size:11px;color:#667eea;text-decoration:none;font-weight:600;margin-right:8px;">&#128272; 2FA</a>
                
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div>
        <div class="info-box">
            <h3>How It Works:</h3>
            <ul>
                <li><b>Step 1:</b> Select your data type (Ticket / Hotel / Ancillary)</li>
                <li><b>Step 2:</b> Upload your CSV file</li>
                <li><b>Step 3:</b> System auto-detects and maps columns</li>
                <li><b>Step 4:</b> Data goes into unified PostgreSQL database</li>
                <li><b>Step 5:</b> Open Power BI and click "Refresh" to see new data</li>
            </ul>
        </div>
        <div class="type-selector">
            <button class="type-btn" data-type="ticket" onclick="selectType('ticket')">Ticket</button>
            <button class="type-btn" data-type="hotel" onclick="selectType('hotel')">Hotel</button>
            <button class="type-btn" data-type="ancillary" onclick="selectType('ancillary')">Ancillary</button>
        </div>
        <form id="uploadForm" enctype="multipart/form-data">
            <input type="hidden" id="sourceType" name="source_type" value="">
            <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                <div style="font-size: 48px; margin-bottom: 15px;">&#128193;</div>
                <p><strong>Click to upload CSV file</strong></p>
                <p style="font-size: 12px; color: #999; margin-top: 8px;">or drag and drop here</p>
                <input type="file" id="fileInput" name="file" accept=".csv" onchange="handleFileSelect(this)">
            </div>
            <p id="fileName" style="text-align: center; color: #667eea; font-weight: 600; margin-bottom: 15px;"></p>
            <button type="submit" class="btn" id="uploadBtn" disabled>Upload to Database</button>
        </form>
        <div id="status" class="status"></div>
        <div id="preview" style="display:none;">
            <h3 style="margin-top: 15px; margin-bottom: 8px; color: #333; font-size: 14px;">Preview (First 5 rows):</h3>
            <div id="previewTable"></div>
            <div class="stats" id="stats"></div>
        </div>
    </div>
    <script>
        let selectedFile = null, selectedType = null;
        function selectType(type) {
            selectedType = type;
            document.getElementById('sourceType').value = type;
            document.querySelectorAll('.type-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelector(`[data-type="${type}"]`).classList.add('active');
            checkReady();
        }
        function handleFileSelect(input) {
            if (input.files && input.files[0]) {
                selectedFile = input.files[0];
                document.getElementById('fileName').textContent = 'Selected: ' + selectedFile.name + ' (' + (selectedFile.size/1024).toFixed(1) + ' KB)';
                checkReady();
            }
        }
        function checkReady() {
            document.getElementById('uploadBtn').disabled = !(selectedFile && selectedType);
        }
        const uploadArea = document.querySelector('.upload-area');
        uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.style.background = '#f0f4ff'; });
        uploadArea.addEventListener('dragleave', () => { uploadArea.style.background = '#fafbff'; });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault(); uploadArea.style.background = '#fafbff';
            if (e.dataTransfer.files.length > 0) {
                document.getElementById('fileInput').files = e.dataTransfer.files;
                handleFileSelect(document.getElementById('fileInput'));
            }
        });
        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!selectedFile || !selectedType) return;
            const status = document.getElementById('status');
            const btn = document.getElementById('uploadBtn');
            status.className = 'status loading';
            status.textContent = 'Processing... Please wait.';
            btn.disabled = true;
            const formData = new FormData();
            formData.append('file', selectedFile);
            formData.append('source_type', selectedType);
            try {
                const response = await fetch('/upload', { method: 'POST', body: formData });
                const result = await response.json();
                if (response.ok) {
                    status.className = 'status success';
                    status.innerHTML = 
                        '<strong>Upload Successful!</strong><br>' +
                        '&#128202; <b>' + result.records_inserted + '</b> ' + result.source_type + ' records inserted<br>' +
                        '&#128193; File: ' + result.file_name + '<br>' +
                        '&#9200; Processing time: ' + result.processing_time + '<br>' +
                        '&#128100; Uploaded by: <b>' + (result.uploaded_by || 'Unknown') + '</b><br>' +
                        '&#128197; Date & Time: <b>' + (result.upload_date || 'N/A') + '</b><br>' +
                        '&#128176; Total Revenue: <b>' + result.stats.total_revenue + '</b> | ' +
                        'Profit: <b>' + result.stats.total_profit + '</b><br><br>' +
                        '<a href="/history" style="color:#667eea;font-weight:600;">&#128220; View Upload History</a> &nbsp;|&nbsp; ' +
                        '<strong>Next:</strong> Open Power BI and click "Refresh"';
                    if (result.preview && result.preview.length > 0) showPreview(result.preview, result.stats);
                } else {
                    status.className = 'status error';
                    status.innerHTML = '<strong>Error:</strong> ' + (result.detail || 'Upload failed');
                }
            } catch (error) {
                status.className = 'status error';
                status.innerHTML = '<strong>Error:</strong> ' + error.message;
            }
            btn.disabled = false;
        });
        function showPreview(data, stats) {
            const preview = document.getElementById('preview');
            const tableDiv = document.getElementById('previewTable');
            const statsDiv = document.getElementById('stats');
            let html = '<table class="preview-table"><tr>';
            const columns = Object.keys(data[0]);
            columns.forEach(col => html += '<th>' + col + '</th>');
            html += '</tr>';
            data.forEach(row => {
                html += '<tr>';
                columns.forEach(col => html += '<td>' + (row[col] !== null ? row[col] : '') + '</td>');
                html += '</tr>';
            });
            html += '</table>';
            tableDiv.innerHTML = html;
            const dupCount = stats.duplicate_rows || 0;
            const insertedCount = stats.inserted_rows || stats.total_rows;
            statsDiv.innerHTML = `
                <div class="stat-card"><div class="number">${insertedCount}</div><div class="label">New Records</div></div>
                <div class="stat-card"><div class="number">${stats.total_revenue}</div><div class="label">Total Revenue</div></div>
                <div class="stat-card"><div class="number">${stats.total_profit}</div><div class="label">Total Profit</div></div>
                ${dupCount > 0 ? `<div class="stat-card" style="background:#fef3c7;"><div class="number" style="color:#92400e;">${dupCount}</div><div class="label">Duplicates Skipped</div></div>` : ''}
            `;
            preview.style.display = 'block';
        }
        async function logout() {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/login';
        }
    </script>
</body>
</html>
"""

# ============================================================
# HISTORY PAGE HTML
# ============================================================
HISTORY_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Travel Analytics - Upload History</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            padding: 30px 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 35px;
            max-width: 1100px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        h1 { color: #333; font-size: 24px; }
        .user-info { font-size: 12px; color: #666; text-align: right; }
        .user-info strong { color: #667eea; }
        .back-btn {
            background: #f0f4ff; color: #667eea; border: 1px solid #667eea;
            padding: 8px 18px; border-radius: 8px; font-size: 13px; cursor: pointer;
            font-weight: 600; text-decoration: none; display: inline-block;
        }
        .back-btn:hover { background: #667eea; color: white; }
        .history-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
        .history-table th, .history-table td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        .history-table th { background: #667eea; color: white; font-weight: 600; }
        .history-table tr:nth-child(even) { background: #f8f9ff; }
        .history-table tr:hover { background: #e0e7ff; }
        .badge {
            display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 11px; font-weight: 600;
        }
        .badge-ticket { background: #dbeafe; color: #1e40af; }
        .badge-hotel { background: #d1fae5; color: #065f46; }
        .badge-ancillary { background: #fef3c7; color: #92400e; }
        .badge-success { background: #d1fae5; color: #065f46; }
        .summary { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 12px; margin-bottom: 20px; }
        .summary-card { background: #f0f4ff; padding: 15px; border-radius: 10px; text-align: center; }
        .summary-card .number { font-size: 22px; font-weight: bold; color: #667eea; }
        .summary-card .label { font-size: 12px; color: #666; margin-top: 4px; }
        .empty-state { text-align: center; padding: 40px; color: #888; }
        .filter-bar {
            display: flex; gap: 12px; align-items: center; flex-wrap: wrap;
            background: #f8f9ff; padding: 15px; border-radius: 10px; margin-bottom: 20px;
        }
        .filter-bar label { font-size: 12px; font-weight: 600; color: #555; }
        .filter-bar input[type="date"] {
            padding: 8px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 13px;
        }
        .filter-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 8px 18px; border-radius: 6px;
            font-size: 13px; font-weight: 600; cursor: pointer;
        }
        .filter-btn:hover { opacity: 0.9; }
        .download-btn {
            background: #10b981; color: white; border: none; padding: 8px 18px;
            border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;
            text-decoration: none; display: inline-block;
        }
        .download-btn:hover { background: #059669; }
        .clear-btn {
            background: #f3f4f6; color: #666; border: 1px solid #ddd;
            padding: 8px 14px; border-radius: 6px; font-size: 13px; cursor: pointer;
        }
        .clear-btn:hover { background: #e5e7eb; }
        .results-info { font-size: 12px; color: #888; margin-bottom: 10px; }
        .pagination { display: flex; gap: 6px; justify-content: center; margin-top: 15px; }
        .pagination button {
            padding: 6px 12px; border: 1px solid #e2e8f0; background: white;
            border-radius: 6px; cursor: pointer; font-size: 12px;
        }
        .pagination button.active { background: #667eea; color: white; border-color: #667eea; }
        .pagination button:hover:not(.active) { background: #f0f4ff; }
        .pagination button:disabled { opacity: 0.5; cursor: not-allowed; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Upload History</h1>
                <p style="color:#666;font-size:13px;">All your previous uploads</p>
            </div>
            <div class="user-info">
                <div>Signed in as <strong>__USER_NAME__</strong></div>
                
                <a href="/" class="back-btn">&#8592; Back to Upload</a>
            </div>
        </div>
        __SUMMARY_CARDS__

        <div class="filter-bar">
            <label>From:</label>
            <input type="date" id="dateFrom" value="__DATE_FROM__">
            <label>To:</label>
            <input type="date" id="dateTo" value="__DATE_TO__">
            <button class="filter-btn" onclick="applyFilter()">&#128269; Filter</button>
            <button class="clear-btn" onclick="clearFilter()">Clear</button>
            <a class="download-btn" href="/api/history/export?__DOWNLOAD_PARAMS__" id="downloadLink">&#128229; Download CSV</a>
        </div>

        <div class="results-info" id="resultsInfo"></div>

        __TABLE__

        <div class="pagination" id="pagination"></div>
    </div>
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        let currentPage = parseInt(urlParams.get('page')) || 1;
        let totalPages = __TOTAL_PAGES__;

        function applyFilter() {
            const from = document.getElementById('dateFrom').value;
            const to = document.getElementById('dateTo').value;
            let url = '/history?page=1';
            if (from) url += '&from=' + from;
            if (to) url += '&to=' + to;
            window.location.href = url;
        }

        function clearFilter() {
            window.location.href = '/history';
        }

        function goToPage(page) {
            const from = document.getElementById('dateFrom').value;
            const to = document.getElementById('dateTo').value;
            let url = '/history?page=' + page;
            if (from) url += '&from=' + from;
            if (to) url += '&to=' + to;
            window.location.href = url;
        }

        // Build pagination
        if (totalPages > 1) {
            const pag = document.getElementById('pagination');
            let html = '';
            html += '<button ' + (currentPage <= 1 ? 'disabled' : '') + ' onclick="goToPage(' + (currentPage-1) + ')">&larr; Prev</button>';
            for (let i = 1; i <= totalPages; i++) {
                if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
                    html += '<button class="' + (i === currentPage ? 'active' : '') + '" onclick="goToPage(' + i + ')">' + i + '</button>';
                } else if (i === currentPage - 3 || i === currentPage + 3) {
                    html += '<span style="padding:6px 4px;">...</span>';
                }
            }
            html += '<button ' + (currentPage >= totalPages ? 'disabled' : '') + ' onclick="goToPage(' + (currentPage+1) + ')">Next &rarr;</button>';
            pag.innerHTML = html;
        }

        async function logout() {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/login';
        }
    </script>
</body>
</html>
"""

# ============================================================
# ROUTES — AUTHENTICATION
# ============================================================

@app.get("/login", response_class=HTMLResponse)
async def login_page(response: Response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return LOGIN_HTML

@app.get("/register", response_class=HTMLResponse)
async def register_page(response: Response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return REGISTER_HTML

@app.get("/setup-2fa", response_class=HTMLResponse)
async def setup_2fa_page(request: Request):
    user = await get_user_or_none(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    response = HTMLResponse(content=SETUP_2FA_HTML)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.post("/api/login/step1")
async def login_step1(request: Request, data: LoginStep1Request, response: Response):
    """Step 1: Verify password. If 2FA enabled, return temp token."""
    email = data.email.strip().lower()
    print(f"[LOGIN STEP 1] Attempt for email: {email}")

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "SELECT user_id, email, full_name, password_hash, is_active, is_2fa_enabled, totp_secret FROM users WHERE email = %s",
        (email,)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

   
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    log_audit(user["user_id"], "login_step1", request.client.host, request.headers.get("user-agent"))

    if user["is_2fa_enabled"]:
        print(f"[LOGIN STEP 1] 2FA is ENABLED for user {user['user_id']}. Issuing temp token.")
        temp_token = create_access_token(
            {"sub": str(user["user_id"]), "email": email, "step": "2fa_pending"},
            expires_delta=timedelta(minutes=5)
        )
        return {
            "requires_2fa": True,
            "temp_token": temp_token,
            "message": "Please enter your 6-digit code from your authenticator app"
        }

    print(f"[LOGIN STEP 1] 2FA is DISABLED for user {user['user_id']}. Issuing full tokens.")
    return await issue_tokens(response, user, request)

@app.post("/api/login/step2")
async def login_step2(request: Request, data: LoginStep2Request, response: Response):
    """Step 2: Verify TOTP and issue full JWT tokens."""
    print(f"[LOGIN STEP 2] Received TOTP code: {data.totp_code}")
    payload = verify_token(data.temp_token, "access")
    if not payload or payload.get("step") != "2fa_pending":
        raise HTTPException(status_code=401, detail="Invalid or expired session. Please log in again.")

    user_id = int(payload["sub"])

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "SELECT user_id, email, full_name, is_active, totp_secret FROM users WHERE user_id = %s",
        (user_id,)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account not found or deactivated")

    print(f"[LOGIN STEP 2] Verifying TOTP against secret for user {user_id}")
    if not verify_totp_code(user["totp_secret"], data.totp_code):
        print(f"[LOGIN STEP 2] TOTP verification FAILED for user {user_id}")
        log_audit(user_id, "2fa_fail", request.client.host, request.headers.get("user-agent"))
        raise HTTPException(status_code=401, detail="Invalid 2FA code. Please try again.")

    print(f"[LOGIN STEP 2] TOTP verification SUCCESS for user {user_id}. Issuing tokens.")
    log_audit(user_id, "2fa_success", request.client.host, request.headers.get("user-agent"))
    return await issue_tokens(response, user, request)

@app.post("/api/refresh")
async def refresh_token(request: Request, response: Response):
    """Rotate refresh token and issue new access token."""
    refresh_token_str = request.cookies.get("refresh_token")
    if not refresh_token_str:
        body = await request.json()
        refresh_token_str = body.get("refresh_token")

    if not refresh_token_str:
        raise HTTPException(status_code=401, detail="No refresh token provided")

    payload = verify_token(refresh_token_str, "refresh")
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
    user_id = int(payload["sub"])

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "SELECT token_id, revoked_at FROM refresh_tokens WHERE token_hash = %s AND user_id = %s",
        (token_hash, user_id)
    )
    token_record = cur.fetchone()

    if not token_record or token_record["revoked_at"]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired")

    # Revoke old token
    cur.execute("UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = %s", (token_record["token_id"],))

    # Get user
    cur.execute("SELECT user_id, email, full_name, is_active FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    if not user or not user["is_active"]:
        raise HTTPException(status_code=403, detail="User not found or deactivated")

    return await issue_tokens(response, user, request)

@app.post("/api/logout")
async def api_logout(request: Request, response: Response):
    """Revoke refresh token and clear cookies."""
    refresh_token_str = request.cookies.get("refresh_token")
    if refresh_token_str:
        token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = %s",
            (token_hash,)
        )
        conn.commit()
        cur.close()
        conn.close()

    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"success": True, "message": "Logged out successfully"}

class RegisterRequest(BaseModel):
    full_name: str
    email: str
    password: str
    department: str = "General"

@app.post("/api/register")
async def api_register(data: RegisterRequest):
    """Register a new user account."""
    email = data.email.strip().lower()
    full_name = data.full_name.strip()
    department = data.department.strip()

    if not email or not full_name or not department or not data.password:
        raise HTTPException(status_code=400, detail="All fields are required")
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    password_hash = hash_password(data.password)

    conn = get_db_connection()
    cur = conn.cursor()

    # Check if email already exists
    cur.execute("SELECT user_id FROM users WHERE email = %s", (email,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Email already registered")

    # Insert new user (role defaults to 'user')
    cur.execute(
        "INSERT INTO users (email, password_hash, full_name, department, is_active, role) VALUES (%s, %s, %s, %s, TRUE, 'user') RETURNING user_id",
        (email, password_hash, full_name, department)
    )
    new_user_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return {"success": True, "message": "Account created successfully", "user_id": new_user_id}

@app.get("/api/users")
async def api_list_users(admin: dict = Depends(require_admin)):
    """List all users (admin only)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "SELECT user_id, email, full_name, department, is_active, role, created_at, last_login_at FROM users ORDER BY created_at DESC"
    )
    users = cur.fetchall()
    cur.close()
    conn.close()
    return {"users": users, "count": len(users)}

@app.post("/api/users/{user_id}/toggle")
async def api_toggle_user(user_id: int, admin: dict = Depends(require_admin)):
    """Toggle user active status (admin only)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Get current status
    cur.execute("SELECT is_active, email FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent deactivating yourself
    if user["email"] == admin["email"]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="You cannot deactivate your own account")

    new_status = not user["is_active"]
    cur.execute("UPDATE users SET is_active = %s WHERE user_id = %s", (new_status, user_id))
    conn.commit()
    cur.close()
    conn.close()

    return {"success": True, "is_active": new_status, "message": f"User {'activated' if new_status else 'deactivated'}"}

@app.post("/api/users/{user_id}/reset-password")
async def api_reset_password(user_id: int, request: Request, admin: dict = Depends(require_admin)):
    """Reset a user's password (admin only)."""
    body = await request.json()
    new_password = body.get("password", "")

    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    password_hash = hash_password(new_password)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE user_id = %s", (password_hash, user_id))
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    conn.commit()
    cur.close()
    conn.close()

    return {"success": True, "message": "Password reset successfully"}

@app.delete("/api/users/{user_id}")
async def api_delete_user(user_id: int, admin: dict = Depends(require_admin)):
    """Delete a user (admin only)."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent deleting yourself
    if user["email"] == admin["email"]:
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="You cannot delete your own account")

    # Prevent deleting the hardcoded admin
    if user["email"] == "":
        cur.close()
        conn.close()
        raise HTTPException(status_code=403, detail="Cannot delete the system admin account")

    cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    return {"success": True, "message": "User deleted successfully"}

# ============================================================
# ROUTES — 2FA MANAGEMENT
# ============================================================

@app.post("/api/2fa/setup")
async def setup_2fa(request: Request, user: dict = Depends(get_current_user)):
    """Generate TOTP secret and QR code for user to scan."""
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user["email"])
    qr_base64 = generate_qr_base64(uri)

    return {
        "secret": secret,
        "qr_uri": uri,
        "qr_base64": qr_base64,
        "message": "Scan this QR code with Google Authenticator, then verify with a code to enable 2FA"
    }

@app.post("/api/2fa/verify-and-enable")
async def verify_and_enable_2fa(
    request: Request,
    code: str = Form(...),
    secret: str = Form(...),
    user: dict = Depends(get_current_user)
):
    """Verify the first TOTP code and permanently enable 2FA."""
    if not verify_totp_code(secret, code):
        raise HTTPException(status_code=400, detail="Invalid code. Please try again.")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET totp_secret = %s, is_2fa_enabled = TRUE WHERE user_id = %s",
        (secret, user["user_id"])
    )
    conn.commit()
    cur.close()
    conn.close()

    log_audit(user["user_id"], "2fa_enabled", request.client.host, request.headers.get("user-agent"))
    return {"success": True, "message": "2FA enabled successfully"}

@app.post("/api/2fa/disable")
async def disable_2fa(
    request: Request,
    code: str = Form(...),
    user: dict = Depends(get_current_user)
):
    """Disable 2FA after verifying a current code."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT totp_secret FROM users WHERE user_id = %s", (user["user_id"],))
    result = cur.fetchone()
    cur.close()
    conn.close()

    if not result or not result["totp_secret"]:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    if not verify_totp_code(result["totp_secret"], code):
        raise HTTPException(status_code=400, detail="Invalid 2FA code")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET totp_secret = NULL, is_2fa_enabled = FALSE WHERE user_id = %s",
        (user["user_id"],)
    )
    conn.commit()
    cur.close()
    conn.close()

    log_audit(user["user_id"], "2fa_disabled", request.client.host, request.headers.get("user-agent"))
    return {"success": True, "message": "2FA disabled"}

@app.get("/api/2fa/status")
async def get_2fa_status(user: dict = Depends(get_current_user)):
    """Check if 2FA is enabled for current user."""
    return {
        "is_2fa_enabled": user.get("is_2fa_enabled", False),
        "user": user["full_name"]
    }

# ============================================================
# ROUTES — PROTECTED PAGES
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = await get_user_or_none(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    html = UPLOAD_HTML_TEMPLATE.replace("__USER_NAME__", user.get("full_name", "User"))
    admin_links = '<a href="/users" style="font-size:11px;color:#667eea;text-decoration:none;font-weight:600;margin-right:8px;">&#128100; Users</a>' if user.get("role") == "admin" else ""
    html = html.replace("__ADMIN_LINKS__", admin_links)
    response = HTMLResponse(content=html)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    user = await get_user_or_none(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute(
            "SELECT upload_id, file_name, source_type, record_count, upload_date, status "
            "FROM uploads WHERE user_id = %s ORDER BY upload_date DESC",
            (user["user_id"],)
        )
        uploads = cur.fetchall()

        cur.execute(
            "SELECT COUNT(*) as total_uploads, COALESCE(SUM(record_count), 0) as total_records "
            "FROM uploads WHERE user_id = %s",
            (user["user_id"],)
        )
        summary = cur.fetchone()

        cur.close()
        conn.close()

        total_uploads = summary["total_uploads"] if summary else 0
        total_records = summary["total_records"] if summary else 0

        summary_html = f"""
        <div class="summary">
            <div class="summary-card"><div class="number">{total_uploads}</div><div class="label">Total Uploads</div></div>
            <div class="summary-card"><div class="number">{total_records:,}</div><div class="label">Total Records</div></div>
            <div class="summary-card"><div class="number">{len(uploads)}</div><div class="label">Recent Uploads</div></div>
        </div>
        """

        if uploads:
            table_html = """
            <table class="history-table">
                <tr>
                    <th>#</th>
                    <th>File Name</th>
                    <th>Type</th>
                    <th>Records</th>
                    <th>Date & Time</th>
                    <th>Status</th>
                </tr>
            """
            for i, u in enumerate(uploads, 1):
                badge_class = f"badge-{u['source_type']}"
                status_badge = '<span class="badge badge-success">success</span>'
                date_str = u['upload_date'].strftime("%Y-%m-%d %H:%M") if u['upload_date'] else 'N/A'
                table_html += f"""
                <tr>
                    <td>{i}</td>
                    <td>{u['file_name']}</td>
                    <td><span class="badge {badge_class}">{u['source_type']}</span></td>
                    <td>{u['record_count']:,}</td>
                    <td>{date_str}</td>
                    <td>{status_badge}</td>
                </tr>
                """
            table_html += "</table>"
        else:
            table_html = '<div class="empty-state"><div style="font-size:40px;margin-bottom:10px;">&#128193;</div><p>No uploads found yet.</p><p style="font-size:12px;">Go back to the upload page to add your first dataset.</p></div>'

        html = HISTORY_HTML_TEMPLATE.replace("__USER_NAME__", user.get("full_name", "User"))
        html = html.replace("__SUMMARY_CARDS__", summary_html)
        html = html.replace("__TABLE__", table_html)
        response = HTMLResponse(content=html)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    except Exception as e:
        return HTMLResponse(content=f"<h2>Error loading history</h2><p>{str(e)}</p><a href='/'>Back</a>")

# ============================================================
# UPLOAD (protected)
# ============================================================

def clean_numeric(value):
    if pd.isna(value) or value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    cleaned = str(value).replace(",", "").replace(" ", "").strip()
    try:
        return float(cleaned)
    except:
        return 0.0

def clean_date(value):
    if pd.isna(value) or value is None or str(value).strip() == "":
        return None
    try:
        for fmt in ["%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d", "%d-%m-%Y"]:
            try:
                return datetime.strptime(str(value).strip(), fmt).date()
            except:
                continue
        return pd.to_datetime(value).date()
    except:
        return None

def detect_source_type(df):
    cols = [c.strip().lower() for c in df.columns]
    if "ticket" in cols or "pnr no" in cols or "airline" in cols or "sector" in cols:
        return "ticket"
    elif "hotel name" in cols or "no of nights" in cols or "no of rooms" in cols:
        return "hotel"
    elif "service name" in cols or "particulars" in cols:
        return "ancillary"
    return "ticket"

def get_col(df, possible_names):
    df_cols = {c.strip().lower(): c.strip() for c in df.columns}
    for name in possible_names:
        if name.lower() in df_cols:
            return df_cols[name.lower()]
    return None


# ============================================================
# MODULE-LEVEL CSV HELPER FUNCTIONS (used by upload and duplicate detection)
# ============================================================

def clean_numeric(value):
    if pd.isna(value) or value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    cleaned = str(value).replace(",", "").replace(" ", "").strip()
    try:
        return float(cleaned)
    except:
        return 0.0

def clean_date(value):
    if pd.isna(value) or value is None or str(value).strip() == "":
        return None
    try:
        for fmt in ["%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d", "%d-%m-%Y"]:
            try:
                return datetime.strptime(str(value).strip(), fmt).date()
            except:
                continue
        return pd.to_datetime(value).date()
    except:
        return None

def get_col(df, possible_names):
    df_cols = {c.strip().lower(): c.strip() for c in df.columns}
    for name in possible_names:
        if name.lower() in df_cols:
            return df_cols[name.lower()]
    return None

def gv(df, row, names, default=None):
    """Get string value from CSV row by possible column names."""
    col = get_col(df, names)
    if col:
        val = row.get(col)
        if pd.notna(val) and str(val).strip() not in ['', 'NaN', 'nan', 'None', 'null']:
            return str(val).strip()
    return default

def gn(df, row, names, default=0.0):
    """Get numeric value from CSV row by possible column names."""
    col = get_col(df, names)
    if col:
        return clean_numeric(row.get(col))
    return default

def gd(df, row, names):
    """Get date value from CSV row by possible column names."""
    col = get_col(df, names)
    if col:
        return clean_date(row.get(col))
    return None

# ============================================================
# DUPLICATE DETECTION & HANDLING
# ============================================================

def get_duplicate_key_field(source_type: str):
    """Return the column name to check for duplicates based on source type."""
    if source_type == "ticket":
        return "ticket_number"
    elif source_type == "hotel":
        return "voucher_no"
    elif source_type == "ancillary":
        return "lpo_no"
    return "doc_no"  # fallback

def get_csv_duplicate_value(df, row, source_type: str):
    """Extract the duplicate key value from a CSV row."""
    if source_type == "ticket":
        # Check ticket_number first, then fall back to doc_no
        val = gv(df, row, ["Ticket", "Ticket Number", "TicketNo"])
        if val:
            return val, "ticket_number"
        val = gv(df, row, ["Doc No", "DocNo"])
        if val:
            return val, "doc_no"
    elif source_type == "hotel":
        val = gv(df, row, ["Voucher No", "VoucherNo", "Voucher"])
        if val:
            return val, "voucher_no"
        val = gv(df, row, ["Doc No", "DocNo"])
        if val:
            return val, "doc_no"
    elif source_type == "ancillary":
        val = gv(df, row, ["Lpo No", "LPO No", "LpoNo"])
        if val:
            return val, "lpo_no"
        val = gv(df, row, ["Doc No", "DocNo"])
        if val:
            return val, "doc_no"

    # Generic fallback
    val = gv(df, row, ["Doc No", "DocNo"])
    if val:
        return val, "doc_no"
    return None, None


@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
    user: dict = Depends(get_current_user)
):
    start_time = datetime.now()
    temp_path = None

    if not file.filename.endswith(('.csv', '.CSV')):
        raise HTTPException(status_code=400, detail="Only CSV files allowed")

    try:
        temp_path = f"temp_{file.filename}"
        with open(temp_path, "wb") as f:
            f.write(await file.read())

        df = pd.read_csv(temp_path, dtype=str, encoding='utf-8-sig')
        df.columns = df.columns.str.strip()
        df = df.dropna(how="all")

        if len(df) == 0:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            raise HTTPException(status_code=400, detail="CSV file is empty")

        detected_type = detect_source_type(df)
        final_type = source_type if source_type and source_type != "auto" else detected_type

        dup_key_field = get_duplicate_key_field(final_type)
        print(f"[UPLOAD] Processing {final_type} file: {file.filename} | Duplicate check field: {dup_key_field}")
        print(f"[UPLOAD] Total rows in CSV: {len(df)}")

        conn = get_db_connection()
        cur = conn.cursor()

        # Using module-level helpers: gv(df, row, names), gn(df, row, names), gd(df, row, names)

        # ============================================================
        # SMART DUPLICATE DETECTION
        # ============================================================

        # Collect all duplicate key values from CSV
        csv_dup_values = []
        row_dup_keys = []  # (index, value, field_name)

        for idx, (_, row) in enumerate(df.iterrows()):
            dup_val, dup_field = get_csv_duplicate_value(df, row, final_type)
            if dup_val:
                csv_dup_values.append(dup_val)
                row_dup_keys.append((idx, dup_val, dup_field))

        existing_in_db = set()
        duplicate_details = []

        if csv_dup_values:
            # Check database for existing records
            # For tickets, we check ticket_number; for others, we check their primary key
            if final_type == "ticket":
                # Check ticket_number first
                cur.execute(
                    "SELECT DISTINCT ticket_number FROM unified_bookings WHERE ticket_number = ANY(%s) AND source_type = %s AND ticket_number IS NOT NULL",
                    (csv_dup_values, final_type)
                )
                ticket_dups = [r[0] for r in cur.fetchall()]
                existing_in_db.update(ticket_dups)

                # Also check doc_no for tickets that don't have ticket_number
                remaining = [v for v in csv_dup_values if v not in ticket_dups]
                if remaining:
                    cur.execute(
                        "SELECT DISTINCT doc_no FROM unified_bookings WHERE doc_no = ANY(%s) AND source_type = %s AND doc_no IS NOT NULL",
                        (remaining, final_type)
                    )
                    doc_dups = [r[0] for r in cur.fetchall()]
                    existing_in_db.update(doc_dups)
            else:
                # For hotel/ancillary, check their primary key field
                cur.execute(
                    f"SELECT DISTINCT {dup_key_field} FROM unified_bookings WHERE {dup_key_field} = ANY(%s) AND source_type = %s AND {dup_key_field} IS NOT NULL",
                    (csv_dup_values, final_type)
                )
                db_dups = [r[0] for r in cur.fetchall()]
                existing_in_db.update(db_dups)

        # Identify which rows are duplicates
        duplicate_rows = set()
        for idx, dup_val, dup_field in row_dup_keys:
            if dup_val in existing_in_db:
                duplicate_rows.add(idx)
                duplicate_details.append({
                    "row": idx + 2,  # +2 for header row and 0-indexing
                    "value": dup_val,
                    "field": dup_field
                })

        total_rows = len(df)
        duplicate_count = len(duplicate_rows)
        new_rows_count = total_rows - duplicate_count

        print(f"[UPLOAD] Duplicates found: {duplicate_count} | New records: {new_rows_count}")

        if new_rows_count == 0:
            cur.close()
            conn.close()
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            raise HTTPException(
                status_code=409,
                detail=f"All {total_rows} records already exist in the database. No new data to upload."
            )

        # Create upload record (track actual new records count)
        cur.execute(
            "INSERT INTO uploads (user_id, file_name, source_type, record_count, status) VALUES (%s,%s,%s,%s,%s) RETURNING upload_id",
            (user["user_id"], file.filename, final_type, new_rows_count, 'success')
        )
        upload_id = cur.fetchone()[0]

        # ============================================================
        # BULK INSERT — skip duplicates
        # ============================================================
        BATCH_SIZE = 5000
        inserted = 0
        batch = []
        skipped_summary = []

        columns = [
            "upload_id", "source_type",
            "booking_date", "doc_no", "client_name", "client_type", "department",
            "passenger_name", "currency", "quantity", "total_revenue", "cost", "profit",
            "service_fee", "commission", "tax_amount", "supplier_name", "agent_name", "remarks",
            "ticket_number", "pnr_number", "airline", "airline_code", "route", "destination", "destination_code", "sector_code",
            "route_type", "travel_date", "departure_date", "return_date", "class_type", "return_class",
            "tour_code", "fare_basis", "booking_source", "published_fare", "original_fare",
            "lowest_fare_offered", "fare_lost_amount",
            "hotel_name", "hotel_city", "hotel_country", "start_date", "end_date", "no_of_nights", "no_of_rooms", "voucher_no",
            "service_name", "from_date", "to_date", "lpo_no", "particulars",
            "departure_time", "arrival_time", "extra_earning", "iata_insurance_payable",
            "iata_insurance_collected", "discount_given", "billing_tax", "cc_charges_collected",
            "sharing_amount", "debited_amount", "glpo_commission", "adm_acm",
            "carbon_emission_value", "reference", "narration", "frequent_flyer_no", "corporate_airline_deals"
        ]

        sql = f"INSERT INTO unified_bookings ({', '.join(columns)}) VALUES %s"

        for idx, (_, row) in enumerate(df.iterrows()):
            # Skip duplicate rows
            if idx in duplicate_rows:
                continue

            booking_date = gd(df, row, ["Issue Date", "Date", "Booking Date"])
            doc_no = gv(df, row, ["Doc No", "DocNo"])
            client_name = gv(df, row, ["Customer Name", "Sub Customer Name"])
            client_type = gv(df, row, ["Corporate Client"])
            department = gv(df, row, ["Cost Centre", "Department"])
            passenger_name = gv(df, row, ["Pax Name"])
            currency = gv(df, row, ["CUR"], "NGN")
            quantity = int(gn(df, row, ["No Of Pax", "No Of Guest", "Quantity"], 1))
            total_revenue = gn(df, row, ["Selling Price"])
            cost = gn(df, row, ["Cost"])
            profit = gn(df, row, ["Profit"])
            service_fee = gn(df, row, ["Service Fee"])
            commission = gn(df, row, ["Comm Amount", "STD Comm Amount"])
            tax_amount = gn(df, row, ["Tax"])
            supplier_name = gv(df, row, ["Supplier Name"])
            agent_name = gv(df, row, ["Agent Name", "Sales Man"])
            remarks = gv(df, row, ["Remarks", "Narration", "Agency Internal Remarks"])

            ticket_number = gv(df, row, ["Ticket"]) if final_type == "ticket" else None
            pnr_number = gv(df, row, ["PNR No"]) if final_type == "ticket" else None
            airline_raw = gv(df, row, ["Airline"]) if final_type == "ticket" else None
            airline_code = None
            airline = airline_raw
            if airline_raw and '-' in airline_raw:
                airline_code = airline_raw.split('-')[0].strip()
                airline = airline_raw.split('-', 1)[1].strip()
            route = gv(df, row, ["Sector"]) if final_type == "ticket" else None
            destination = gv(df, row, ["Destination"]) if final_type == "ticket" else None
            destination_code = gv(df, row, ["Destination Code"]) if final_type == "ticket" else None
            sector_code = gv(df, row, ["Sector Code"]) if final_type == "ticket" else None
            route_type = gv(df, row, ["Region"]) if final_type == "ticket" else None
            travel_date = gd(df, row, ["Travel Date"]) if final_type == "ticket" else None
            departure_date = gd(df, row, ["Departure Date"]) if final_type == "ticket" else None
            return_date = gd(df, row, ["Return Date"]) if final_type == "ticket" else None
            class_type = gv(df, row, ["Class"]) if final_type == "ticket" else None
            return_class = gv(df, row, ["Return Class"]) if final_type == "ticket" else None
            tour_code = gv(df, row, ["Tour Code"]) if final_type == "ticket" else None
            fare_basis = gv(df, row, ["Fare Basis"]) if final_type == "ticket" else None
            booking_source = gv(df, row, ["GDS Company"]) if final_type == "ticket" else None
            published_fare = gn(df, row, ["Published Fare", "Fare Accepted or Paid"]) if final_type == "ticket" else 0
            original_fare = gn(df, row, ["Original Fare"]) if final_type == "ticket" else 0
            lowest_fare_offered = gn(df, row, ["Lowest Fare Offered"]) if final_type == "ticket" else 0
            fare_lost_amount = gn(df, row, ["Fare Lost Amt"]) if final_type == "ticket" else 0

            departure_time = gv(df, row, ["Departure Time"]) if final_type == "ticket" else None
            arrival_time = gv(df, row, ["Arrival Time"]) if final_type == "ticket" else None
            extra_earning = gn(df, row, ["Extra Earning"]) if final_type == "ticket" else 0
            iata_insurance_payable = gn(df, row, ["IATA Insurance Payable"]) if final_type == "ticket" else 0
            iata_insurance_collected = gn(df, row, ["IATA Insurance Collected"]) if final_type == "ticket" else 0
            discount_given = gn(df, row, ["Discount Given"]) if final_type == "ticket" else 0
            billing_tax = gn(df, row, ["Billing Tax"]) if final_type == "ticket" else 0
            cc_charges_collected = gn(df, row, ["CC Charges Collected"]) if final_type == "ticket" else 0
            sharing_amount = gn(df, row, ["Sharing Amount"]) if final_type == "ticket" else 0
            debited_amount = gn(df, row, ["Debited Amount"]) if final_type == "ticket" else 0
            glpo_commission = gn(df, row, ["GLPO Commission"]) if final_type == "ticket" else 0
            adm_acm = gv(df, row, ["ADM/ACM"]) if final_type == "ticket" else None
            carbon_emission_raw = gv(df, row, ["Carbon Emission Value"]) if final_type == "ticket" else None
            carbon_emission_value = None
            if carbon_emission_raw:
                carbon_emission_value = carbon_emission_raw.replace("kg", "").replace("KG", "").replace("Kg", "").strip()
            reference = gv(df, row, ["Reference"]) if final_type == "ticket" else None
            narration = gv(df, row, ["Narration"]) if final_type == "ticket" else None
            frequent_flyer_no = gv(df, row, ["Frequent Flyer No"]) if final_type == "ticket" else None
            corporate_airline_deals = gv(df, row, ["Corporate Airline Deals"]) if final_type == "ticket" else None

            hotel_name = gv(df, row, ["Hotel Name"]) if final_type == "hotel" else None
            hotel_city = gv(df, row, ["City"]) if final_type == "hotel" else None
            hotel_country = gv(df, row, ["Country"]) if final_type == "hotel" else None
            start_date = gd(df, row, ["Start Date"]) if final_type == "hotel" else None
            end_date = gd(df, row, ["Return Date", "End Date"]) if final_type == "hotel" else None
            no_of_nights = int(gn(df, row, ["No Of Nights"], 0)) if final_type == "hotel" else 0
            no_of_rooms = int(gn(df, row, ["No Of Rooms"], 0)) if final_type == "hotel" else 0
            voucher_no = gv(df, row, ["Voucher No"]) if final_type == "hotel" else None

            service_name = gv(df, row, ["Service Name"]) if final_type == "ancillary" else None
            from_date = gd(df, row, ["From Date"]) if final_type == "ancillary" else None
            to_date = gd(df, row, ["To Date"]) if final_type == "ancillary" else None
            lpo_no = gv(df, row, ["Lpo No", "LPO No"]) if final_type == "ancillary" else None
            particulars = gv(df, row, ["Particulars"]) if final_type == "ancillary" else None

            batch.append((
                upload_id, final_type,
                booking_date, doc_no, client_name, client_type, department,
                passenger_name, currency, quantity, total_revenue, cost, profit,
                service_fee, commission, tax_amount, supplier_name, agent_name, remarks,
                ticket_number, pnr_number, airline, airline_code, route, destination, destination_code, sector_code,
                route_type, travel_date, departure_date, return_date, class_type, return_class,
                tour_code, fare_basis, booking_source, published_fare, original_fare,
                lowest_fare_offered, fare_lost_amount,
                hotel_name, hotel_city, hotel_country, start_date, end_date, no_of_nights, no_of_rooms, voucher_no,
                service_name, from_date, to_date, lpo_no, particulars,
                departure_time, arrival_time, extra_earning, iata_insurance_payable,
                iata_insurance_collected, discount_given, billing_tax, cc_charges_collected,
                sharing_amount, debited_amount, glpo_commission, adm_acm,
                carbon_emission_value, reference, narration, frequent_flyer_no, corporate_airline_deals
            ))

            if len(batch) >= BATCH_SIZE:
                execute_values(cur, sql, batch, page_size=BATCH_SIZE)
                inserted += len(batch)
                batch = []
                print(f"  -> Inserted {inserted} rows so far...")

        # Insert remaining rows
        if batch:
            execute_values(cur, sql, batch, page_size=len(batch))
            inserted += len(batch)
            print(f"  -> Final batch: {inserted} total rows inserted.")

        conn.commit()
        cur.close()
        conn.close()

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

        # Calculate stats for NEW records only (skip duplicates)
        total_rev = 0.0
        total_profit = 0.0
        for idx, (_, row) in enumerate(df.iterrows()):
            if idx in duplicate_rows:
                continue
            sp_col = get_col(df, ["Selling Price"])
            if sp_col:
                total_rev += clean_numeric(row.get(sp_col))
            profit_col = get_col(df, ["Profit"])
            if profit_col:
                total_profit += clean_numeric(row.get(profit_col))

        stats = {
            "total_rows": total_rows,
            "inserted_rows": inserted,
            "duplicate_rows": duplicate_count,
            "total_revenue": f"{total_rev:,.2f}",
            "total_profit": f"{total_profit:,.2f}"
        }

        # Build preview from NEW records only
        preview_data = []
        preview_count = 0
        for idx, (_, row) in enumerate(df.iterrows()):
            if idx in duplicate_rows:
                continue
            if preview_count >= 5:
                break
            mapped_row = {
                "booking_date": str(gd(df, row, ["Date"])),
                "client_name": gv(df, row, ["Customer Name", "Sub Customer Name"]),
                "passenger_name": gv(df, row, ["Pax Name"]),
                "destination": gv(df, row, ["Destination"]) if final_type == "ticket" else None,
                "total_revenue": f"{gn(df, row, ['Selling Price']):,.2f}",
                "profit": f"{gn(df, row, ['Profit']):,.2f}"
            }
            preview_data.append(mapped_row)
            preview_count += 1

        processing_time = (datetime.now() - start_time).total_seconds()
        upload_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build duplicate summary for display
        dup_summary = ""
        if duplicate_count > 0:
            dup_list = [f"{d['value']} ({d['field']})" for d in duplicate_details[:10]]
            dup_text = ", ".join(dup_list)
            if duplicate_count > 10:
                dup_text += f" and {duplicate_count - 10} more"
            dup_summary = f"<br>&#9888; <b>{duplicate_count}</b> duplicate(s) skipped: {dup_text}"

        return {
            "status": "success",
            "source_type": final_type,
            "detected_type": detected_type,
            "records_inserted": inserted,
            "records_skipped": duplicate_count,
            "total_records_in_file": total_rows,
            "file_name": file.filename,
            "upload_id": upload_id,
            "processing_time": f"{processing_time:.2f} seconds",
            "uploaded_by": user.get("full_name", "Unknown"),
            "upload_date": upload_timestamp,
            "duplicate_details": duplicate_details[:20],  # First 20 for reference
            "preview": preview_data,
            "stats": stats,
            "message": f"{inserted} new records uploaded. {duplicate_count} duplicate(s) skipped." if duplicate_count > 0 else f"All {inserted} records uploaded successfully.",
            "dup_summary_html": dup_summary
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR: {str(e)}")
        print(traceback.format_exc())
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# API ROUTES — DATA
# ============================================================

@app.get("/api/history/export")
async def export_history(
    request: Request,
    from_date: str = None,
    to_date: str = None,
    user: dict = Depends(get_current_user)
):
    """Export upload history as CSV download."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        where_conditions = ["user_id = %s"]
        params = [user["user_id"]]

        if from_date:
            where_conditions.append("upload_date >= %s")
            params.append(from_date)
        if to_date:
            where_conditions.append("upload_date <= %s")
            params.append(to_date + " 23:59:59")

        where_clause = " AND ".join(where_conditions)

        query = f"""
            SELECT upload_id, file_name, source_type, record_count, 
                   upload_date::date as upload_date, status
            FROM uploads 
            WHERE {where_clause} 
            ORDER BY upload_date DESC
        """
        cur.execute(query, params)
        uploads = cur.fetchall()
        cur.close()
        conn.close()

        if not uploads:
            raise HTTPException(status_code=404, detail="No upload history found for the selected date range")

        # Build CSV in memory
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Upload ID", "File Name", "Type", "Records", "Upload Date", "Status"])

        for u in uploads:
            writer.writerow([
                u["upload_id"],
                u["file_name"],
                u["source_type"],
                u["record_count"],
                u["upload_date"].strftime("%Y-%m-%d") if u["upload_date"] else "",
                u["status"]
            ])

        csv_content = output.getvalue()
        output.close()

        # Build filename with date range
        filename_parts = ["upload_history"]
        if from_date:
            filename_parts.append(f"from_{from_date}")
        if to_date:
            filename_parts.append(f"to_{to_date}")
        filename = "_".join(filename_parts) + ".csv"

        from fastapi.responses import StreamingResponse
        return StreamingResponse(
            io.StringIO(csv_content),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")

@app.get("/api/bookings")
async def get_bookings(user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM vw_unified_bookings ORDER BY booking_date DESC")
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

@app.get("/api/summary")
async def get_summary(user: dict = Depends(get_current_user)):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT COUNT(*) as total_bookings, COALESCE(SUM(total_revenue), 0) as total_revenue,
               COALESCE(SUM(profit), 0) as total_profit, COUNT(DISTINCT client_name) as unique_clients
        FROM unified_bookings
    """)
    overall = cur.fetchone()
    cur.execute("SELECT source_type, COUNT(*) as count, SUM(total_revenue) as revenue FROM unified_bookings GROUP BY source_type ORDER BY revenue DESC")
    by_type = cur.fetchall()
    cur.execute("SELECT client_name, COUNT(*) as count, SUM(total_revenue) as revenue FROM unified_bookings GROUP BY client_name ORDER BY revenue DESC LIMIT 10")
    top_clients = cur.fetchall()
    cur.close()
    conn.close()
    return {"overall": overall, "by_type": by_type, "top_clients": top_clients}

@app.get("/api/debug/user/{email}")
async def debug_user_2fa(email: str):
    """Debug endpoint: Check a user's 2FA status without authentication."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute(
        "SELECT user_id, email, full_name, is_active, is_2fa_enabled, totp_secret IS NOT NULL as has_secret FROM users WHERE email = %s",
        (email.strip().lower(),)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user:
        return {"found": False, "message": "User not found"}
    return {
        "found": True,
        "user_id": user["user_id"],
        "email": user["email"],
        "is_active": user["is_active"],
        "is_2fa_enabled": user["is_2fa_enabled"],
        "has_totp_secret": user["has_secret"]
    }

@app.get("/api/me")
async def get_current_user_info(user: dict = Depends(get_current_user)):
    """Get current authenticated user info."""
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "full_name": user["full_name"],
        "department": user["department"],
        "is_2fa_enabled": user.get("is_2fa_enabled", False)
    }

@app.get("/api/health")
async def health_check(request: Request):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM unified_bookings")
        count = cur.fetchone()[0]
        cur.execute("SELECT source_type, COUNT(*) FROM unified_bookings GROUP BY source_type")
        types = cur.fetchall()
        cur.close()
        conn.close()
        return {
            "status": "healthy",
            "authenticated": bool(request.cookies.get("access_token")),
            "total_records": count,
            "by_type": {t[0]: t[1] for t in types}
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
