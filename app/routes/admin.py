from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from app.database import fetch_all_policies, get_db, set_policy_enabled

router = APIRouter(tags=["admin"])

DASHBOARD_PATH = Path(__file__).parent.parent.parent / "dashboard.html"


@router.get("/admin/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the live admin dashboard."""
    return HTMLResponse(content=DASHBOARD_PATH.read_text(encoding="utf-8"))


@router.get("/admin/policies")
async def list_policies():
    """Return all policies (enabled + disabled) for the policy control panel."""
    with get_db() as conn:
        rows = fetch_all_policies(conn)
    return JSONResponse([dict(r) for r in rows])


class PolicyToggle(BaseModel):
    is_enabled: bool


@router.patch("/admin/policies/{policy_id}")
async def toggle_policy(policy_id: int, body: PolicyToggle):
    """
    Enable or disable a policy at runtime without restarting the server.
    The CBAC middleware re-fetches active policies on every request, so
    the change takes effect immediately on the next inbound request.
    """
    with get_db() as conn:
        # Verify the policy exists
        row = conn.execute(
            "SELECT id, policy_name FROM access_policies WHERE id = ?",
            (policy_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found.")

        set_policy_enabled(conn, policy_id, body.is_enabled)

    return JSONResponse({
        "policy_id":   policy_id,
        "policy_name": row["policy_name"],
        "is_enabled":  body.is_enabled,
        "message":     f"Policy '{row['policy_name']}' {'enabled' if body.is_enabled else 'disabled'}.",
    })
