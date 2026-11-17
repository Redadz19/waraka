from datetime import datetime
from typing import Literal
from pydantic import BaseModel, EmailStr, Field


class LicenseCreate(BaseModel):
    email: EmailStr
    expires_at: datetime | None = None


class OTPRequest(BaseModel):
    serial: str = Field(min_length=8, max_length=80)
    email: EmailStr


class ActivateRequest(BaseModel):
    serial: str = Field(min_length=8, max_length=80)
    email: EmailStr
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")
    device_id: str = Field(min_length=8, max_length=128)
    device_name: str = Field(default="", max_length=200)


class DeactivateRequest(BaseModel):
    serial: str = Field(min_length=8, max_length=80)
    email: EmailStr
    device_id: str = Field(min_length=8, max_length=128)


class VerifyRequest(BaseModel):
    serial: str = Field(min_length=8, max_length=80)
    email: EmailStr
    device_id: str = Field(min_length=8, max_length=128)



class PaymentCheckoutRequest(BaseModel):
    email: EmailStr
    payment_method: Literal["edahabia", "cib", "chargily_app"] = "edahabia"
    locale: Literal["ar", "fr", "en"] = "ar"
