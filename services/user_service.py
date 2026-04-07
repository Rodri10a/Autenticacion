from fastapi import HTTPException


def list_users(db) -> list[dict]:
    users = db.execute(
        "SELECT id, email, role, is_active, created_at FROM users"
    ).fetchall()
    return [
        {
            "id": u["id"],
            "email": u["email"],
            "role": u["role"],
            "is_active": bool(u["is_active"]),
            "created_at": u["created_at"],
        }
        for u in users
    ]


def delete_user(db, user_id: int, current_user_id: int) -> dict:
    if user_id == current_user_id:
        raise HTTPException(
            status_code=400, detail="No podes eliminarte a vos mismo"
        )

    target = db.execute(
        "SELECT id, email FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return {"message": f"Usuario {target['email']} eliminado"}


def get_login_attempts(db, limit: int = 100) -> list[dict]:
    attempts = db.execute(
        "SELECT id, email, ip_address, success, timestamp "
        "FROM login_attempts ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        {
            "id": a["id"],
            "email": a["email"],
            "ip_address": a["ip_address"],
            "success": bool(a["success"]),
            "timestamp": a["timestamp"],
        }
        for a in attempts
    ]
