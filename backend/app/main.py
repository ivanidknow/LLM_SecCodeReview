from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

from app.core.parser import ProtocolParser
from app.api.projects import router as projects_router
from app.api.analysis import router as analysis_router
from app.api.history import router as history_router
from app.api.utils import router as utils_router
from app.api.reporting import router as reporting_router
from app.services.database import init_db

app = FastAPI(title="Security Code Review API")

# CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Methodology path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTOCOL_PATH = os.path.join(BASE_DIR, "..", ".security_review", "guidelines")

parser = ProtocolParser(PROTOCOL_PATH)


@app.on_event("startup")
async def startup_event():
    """Initialize the database tables on startup."""
    await init_db()


@app.get("/api/methodology")
async def get_methodology():
    """Returns the methodology tree for the frontend"""
    tree = parser.get_methodology_tree()
    if not tree:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="No protocols found")
    return tree


# Register API routers
app.include_router(projects_router)
app.include_router(analysis_router)
app.include_router(history_router)
app.include_router(utils_router)
app.include_router(reporting_router, prefix="/api/analysis")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)