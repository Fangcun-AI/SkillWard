from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator


class SkillOperation(BaseModel):
    """Single skill operation record"""
    index: int = Field(..., description="Operation index")
    action: str = Field(..., description="Operation type: read, exec, edit")
    target: str = Field(..., description="Operation target: file path or command")
    details: Optional[str] = Field(None, description="Additional details")


class SkillAuditRequest(BaseModel):
    """Skill audit request model"""
    skill_name: str = Field(..., description="Skill name from SKILL.md")
    skill_description: str = Field(..., description="Skill description from SKILL.md")
    operations: List[SkillOperation] = Field(..., description="Agent executed operations history")
    current_operation: str = Field(..., description="The current operation to judge")
    static_match_level: Optional[str] = Field(None, description="Plugin static match risk level (no_risk/low_risk/medium_risk/high_risk)")
    static_match_reason: Optional[str] = Field(None, description="Plugin static match detail/reason")
    skill_metadata: Optional[Dict[str, Any]] = Field(None, description="Additional skill metadata")

    @validator('operations')
    def validate_operations(cls, v):
        if not v:
            raise ValueError('operations cannot be empty')
        return v
