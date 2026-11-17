from pydantic import BaseModel, EmailStr, Field

class LicenseCreate(BaseModel):
    email: EmailStr
    expires_at: str | None = None

class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)

class ActivateRequest(BaseModel):
    serial: str = Field(min_length=8, max_length=80)
    email: EmailStr
    device_id: str = Field(min_length=8, max_length=128)
    device_name: str = Field(default="", max_length=200)

class DeactivateRequest(BaseModel):
    serial: str
    device_id: str

class VerifyRequest(BaseModel):
    serial: str
    email: EmailStr
    device_id: str
