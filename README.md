[README.md](https://github.com/user-attachments/files/24681009/README.md)
# Servidor de Licencas - Ponto do Acai (Render)

## Deploy no Render (Web Service)
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn main:APP --host 0.0.0.0 --port $PORT`

## Variaveis de ambiente
- `ADMIN_TOKEN`: senha do admin (use um valor forte)
- `LICENSE_DB`: (opcional) caminho do sqlite (padrao: license.db)

## Endpoints
- POST `/api/check`
- POST `/admin/device/authorize` (Header `X-Admin-Token`)
- POST `/admin/device/revoke`
- POST `/admin/company`
- GET `/admin/devices?company_key=...`

> Observacao: Para PRODUCAO, use Postgres (Render managed DB) ou disco persistente; sqlite no free pode ser efemero.
