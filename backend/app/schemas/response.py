from pydantic import BaseModel
from typing import Any

class APIResponse(BaseModel):
    detail: str
    data: Any = None