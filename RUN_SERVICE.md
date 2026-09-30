# Run the anonymizer service

Install Python 3.11 or newer, then clone the repository:

```sh
git clone https://github.com/filtsiap-dev/apodeltiosi_ded.git
cd apodeltiosi_ded
python -m venv .venv
```

Activate the virtual environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
Copy-Item .env.example .env
```

```sh
# Linux/macOS
source .venv/bin/activate
cp .env.example .env
```

Install the pinned dependencies:

```sh
python -m pip install -r requirements.txt
```

Edit `.env`: set `OPENAI_API_KEY`, `ANON_MODEL`, and a long random `ANON_API_KEY`.
For Azure, set `ANON_PROVIDER=azure` and the Azure variables in the template.
Generate a service API key with:

```sh
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Keep `.env` local; never commit credentials. Start from the repository root:

```sh
python -m uvicorn anonymizer.api:app --host 0.0.0.0 --port 8000 --no-proxy-headers
```

Keep `config/` beside `anonymizer/`; it contains required YAML rules and allowlists.
The service loads `.env` automatically. Invalid configuration stops startup.
The process runs in the foreground; use your host's service manager for persistent operation.

Check startup in another terminal:

```sh
curl --fail http://localhost:8000/healthz
```

In Windows PowerShell use `curl.exe` or `Invoke-RestMethod http://localhost:8000/healthz`.
A healthy response confirms startup, not provider access.

To submit a DOCX, set `ANON_API_KEY` in the client shell to the same value used by
the service, then run:

```sh
python examples/anonymize_client.py --url http://localhost:8000 --file input.docx --out output.docx
```

`POST /anonymize` requires Bearer authentication and raw DOCX bytes. Its response
is a DOCX file. The client validates the response; inspect its reported review
status before using the result. Anonymization calls the configured provider and
incurs usage charges. No source-data documents are required to start the service.

Pushing to GitHub stores the code. Pull the latest main branch on your host,
install the pinned dependencies, and restart the service to apply updates.
