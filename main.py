import os
import json
import secrets
from datetime import datetime
from typing import Optional, Tuple

from authlib.integrations.starlette_client import OAuth
from fastapi import Body, Depends, FastAPI, Form, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from packaging.version import parse as parse_version
from pydantic import BaseModel
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, event, text, and_, or_, false
from sqlalchemy.exc import IntegrityError
from starlette.middleware.sessions import SessionMiddleware
from models import Base, User, Team, APIKey, Device, Fleet, Tag, VersionedRelease, OneShotRelease, UserRole, ScopeType, ComputeModule, AllowedEmail, AllowedDomain, ReleaseStatus, UpdateMode
from auth import (
    oauth, hash_api_key, get_current_user_from_db, verify_api_key,
    get_current_user_scopes, verify_api_key_scope_access
)

# =============================================================================
app = FastAPI(title="ESP32 Fleet OTA Server")

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    accept = request.headers.get("accept", "")
    if "text/html" in accept and not request.url.path.startswith("/admin/upload") and not request.url.path.startswith("/check-update"):
        return HTMLResponse(
            status_code=exc.status_code,
            content=f"""
            <html>
                <body style="font-family: sans-serif; text-align: center; padding-top: 100px; background: #f9fafb; color: #333;">
                    <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                        <h1 style="color: #ef4444; margin-top: 0;">Access Denied</h1>
                        <p>{exc.detail}</p>
                        <a href="/login" style="display: inline-block; margin-top: 15px; color: #3b82f6; text-decoration: none;">Return to Login</a>
                    </div>
                </body>
            </html>
            """
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", secrets.token_urlsafe(32))
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET_KEY)

import database
import bootstrap
from routers import auth, admin, ota, firmware, fleet, devices, pages

@app.on_event("startup")
def startup_seed_defaults() -> None:
    bootstrap._seed_allowlist_from_env()
    bootstrap._seed_tag_categories()

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(ota.router)
app.include_router(firmware.router)
app.include_router(fleet.router)
app.include_router(devices.router)
app.include_router(pages.router)
