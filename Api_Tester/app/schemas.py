from pydantic import BaseModel, EmailStr
from typing import Optional

class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    cpf: str
    telefone: str

class UsuarioMasked(BaseModel):
    id: str
    nome: str
    email: str
    cpf_masked: str
    telefone_masked: str

class UsuarioRevealed(BaseModel):
    id: str
    nome: str
    email: str
    cpf: str
    telefone: str

class UsuarioUpdate(BaseModel):
    nome: Optional[str] = None
    email: Optional[EmailStr] = None
    cpf: Optional[str] = None
    telefone: Optional[str] = None
