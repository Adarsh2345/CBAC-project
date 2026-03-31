from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.database import get_db

router = APIRouter(tags=["protected"])


@router.get("/api/payroll")
async def payroll():
    """Mock secure payroll endpoint, gated by the CBAC middleware."""
    return JSONResponse({
        "status":  "success",
        "message": "Secure Payroll Data Accessed",
        "data": [
            {"employee": "Alice", "salary": 95000},
            {"employee": "Bob",   "salary": 87000},
        ],
    })


@router.get("/api/logs")
async def get_logs():
    """Return the 50 most recent access log entries, newest first."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, user_id, username, ip_address, country, city,
                   action, policy_name, reason
            FROM   access_logs
            ORDER  BY id DESC
            LIMIT  50
            """,
        ).fetchall()
    return JSONResponse([dict(r) for r in rows])
