from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from features.security_features import check_keys, coerce
from features.url_features import InvalidUrlError, parse_url


class PredictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., min_length=4, max_length=2048, description="http(s) URL to classify")
    security_features: dict[str, float | bool | None] | None = Field(None, description="Optional signals from other analysis modules (see features/schema.py SECURITY_FEATURES)")
    top_k: int = Field(5, ge=1, le=20)
    explain: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        try:
            parse_url(v)
        except InvalidUrlError as e:
            raise ValueError(str(e)) from None
        return v

    @field_validator("security_features")
    @classmethod
    def _security(cls, v):
        if v:
            check_keys(v)
            for x in v.values():
                coerce(x)
        return v


class FeatureContribution(BaseModel):
    feature: str
    label: str
    value: float | None
    contribution: float = Field(..., description="log-odds contribution; positive pushes toward phishing")
    direction: Literal["phishing", "legitimate"]


class PredictResponse(BaseModel):
    prediction: Literal["phishing", "legitimate"]
    probability: float = Field(..., ge=0, le=1, description="P(phishing)")
    confidence: float = Field(..., ge=0, le=1)
    top_features: list[FeatureContribution]
    explanation: list[str]
    model_version: str
    explanation_method: str | None
    ignored_features: list[str] = []


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., min_length=4, max_length=2048)
    inspect_website: bool = Field(True, description="Fetch and statically inspect the page HTML")
    include_ml: bool = Field(True, description="Include the ML prediction when a model is loaded")

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        try:
            parse_url(v)
        except InvalidUrlError as e:
            raise ValueError(str(e)) from None
        return v
