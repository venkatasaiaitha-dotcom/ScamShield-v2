from .agent import router as agent_router
from .messages import router as messages_router
from .alerts import router as alerts_router
from .history import router as history_router
from .sources import router as sources_router
from .settings import router as settings_router
from .gmail import router as gmail_router
from .auth import router as auth_router
from .security_status import router as security_router
from .community import router as community_router
from .investigate import router as investigate_router

__all__ = [
    "agent_router",
    "messages_router",
    "alerts_router",
    "history_router",
    "sources_router",
    "settings_router",
    "gmail_router",
    "auth_router",
    "security_router",
    "community_router",
    "investigate_router"
]
