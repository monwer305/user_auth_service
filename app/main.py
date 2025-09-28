from fastapi import FastAPI
from app.auth import routes as auth_routes
from app.users import routes as user_routes
from app.bootstrap import bootstrap

app = FastAPI(title="Auth Service with Roles")

# Include routers
app.include_router(auth_routes.router)
app.include_router(user_routes.router)

# Run bootstrap on startup
@app.on_event("startup")
def on_startup():
    bootstrap()

@app.get("/")
def health():
    return {"status": "ok"}
