from pydantic import BaseModel, Field


class SkillAuditResponse(BaseModel):
    """Skill audit response model"""
    id: str
    risk_level: int = Field(..., description="Risk level: 0=normal, 1=low, 2=medium, 3=high")
    risk_label: str = Field(..., description="Risk label: normal, low_risk, medium_risk, high_risk")
    classification: str = Field(..., description="Classification model output (e.g., Safety: Safe)")
    analysis: str = Field(..., description="LLM analysis reasoning")
    remediation: str = Field("", description="Suggested fix or mitigation for the detected risk")
    suggest_action: str = Field(..., description="Suggested action: pass, warn, block")
