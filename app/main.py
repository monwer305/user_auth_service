from fastapi import FastAPI, status

from app.auth import routes as auth_routes
from app.users import routes as user_routes

app = FastAPI(prefix="v1/auth", title="Auth Service with Roles")

# Include routers
app.include_router(auth_routes.router)
app.include_router(user_routes.router)


@app.get("/status", status_code=status.HTTP_200_OK)
def health():
    return {"status": "ok"}
