from fastapi import APIRouter
from app.api.v1 import auth, dashboard, health, members, resources, workflows

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
for r in resources.resource_routers:
    api_router.include_router(r)
api_router.include_router(members.router)
api_router.include_router(dashboard.router)
api_router.include_router(workflows.router)
