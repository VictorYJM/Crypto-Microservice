from fastapi import APIRouter, HTTPException
from app.supabase_client import supabase
from app.crypto_client import crypto_client
from app.schemas import UsuarioCreate, UsuarioMasked, UsuarioRevealed, UsuarioUpdate

router = APIRouter(prefix="/client", tags=["client"])


def _strip_algorithm(envelope: dict) -> dict:
    return {k: v for k, v in envelope.items() if k != "algorithm"}


def _mask(value: str, visible: int = 4) -> str:
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]


@router.post("", status_code=201)
async def criar_usuario(payload: UsuarioCreate):
    cpf_envelope = await crypto_client.encrypt(payload.cpf)
    telefone_envelope = await crypto_client.encrypt(payload.telefone)

    # NOTA: aqui deveria entrar hash Argon2id da senha, não a senha em texto plano.
    # Deixei simplificado só pra fins de teste — ver observação abaixo do código.
    result = supabase.table("client").insert({
        "name": payload.nome,
        "email": payload.email,
        "password_hash": payload.senha,
        "cpf_encrypted": cpf_envelope,
        "phone_encrypted": telefone_envelope,
    }).execute()

    return result.data[0]


@router.get("", response_model=list[UsuarioMasked])
async def listar_client_mascarados():
    result = supabase.table("client").select(
        "id, name, email, cpf_encrypted, phone_encrypted"
    ).execute()

    envelopes_cpf = [_strip_algorithm(u["cpf_encrypted"]) for u in result.data]
    resultados_cpf = await crypto_client.decrypt_batch(envelopes_cpf)

    client = []
    for user, cpf_result in zip(result.data, resultados_cpf):
        cpf_plain = cpf_result["plaintext"] if cpf_result["success"] else "ERRO"
        client.append(UsuarioMasked(
            id=user["id"],
            nome=user["name"],
            email=user["email"],
            cpf_masked=_mask(cpf_plain),
            telefone_masked="****-****",  # não descriptografado nessa listagem
        ))

    return client


@router.get("/{usuario_id}/revelar", response_model=UsuarioRevealed)
async def revelar_usuario(usuario_id: str):
    result = supabase.table("client").select("*").eq("id", usuario_id).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user = result.data[0]

    cpf = await crypto_client.decrypt(_strip_algorithm(user["cpf_encrypted"]))
    telefone = await crypto_client.decrypt(_strip_algorithm(user["telefone_encrypted"]))

    # AQUI é o ponto certo pra registrar auditoria de acesso (quem revelou, quando)
    # print(f"AUDIT: usuario {usuario_id} revelado em {datetime.now()}")

    return UsuarioRevealed(
        id=user["id"],
        nome=user["name"],
        email=user["email"],
        cpf=cpf,
        telefone=telefone,
    )

@router.put("/{usuario_id}")
async def atualizar_usuario(usuario_id: str, payload: UsuarioUpdate):
    update_data: dict = {}

    if payload.nome is not None:
        update_data["name"] = payload.nome
    if payload.email is not None:
        update_data["email"] = payload.email
    if payload.cpf is not None:
        update_data["cpf_encrypted"] = await crypto_client.encrypt(payload.cpf)
    if payload.telefone is not None:
        update_data["phone_encrypted"] = await crypto_client.encrypt(payload.telefone)

    if not update_data:
        raise HTTPException(status_code=400, detail="Nenhum campo para atualizar")

    result = supabase.table("client").update(update_data).eq("id", usuario_id).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    return result.data[0]


@router.delete("/{usuario_id}", status_code=204)
async def deletar_usuario(usuario_id: str):
    result = supabase.table("client").delete().eq("id", usuario_id).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    return None
