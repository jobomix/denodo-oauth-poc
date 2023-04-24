import string

import pkce
import random
import aiohttp
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()
states = {}

authorize_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"


@app.get("/authorize")
async def authorize_url(client_id: str,
                        aad=authorize_url,
                        response_type="code",
                        scope="openid",
                        redirect_uri="http://localhost:8000"):
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    states[state] = {"code_verifier": code_verifier, "client_id": client_id, "redirect_uri": redirect_uri}
    url = f"{aad}?response_type={response_type}&client_id={client_id}&scope={scope}&redirect_uri={redirect_uri}" \
          f"&code_challenge={code_challenge}&code_challenge_method=S256&state={state}"
    return url


@app.get("/challenge")
async def challenge():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    states[state] = code_verifier
    res = {"state": state, "challenge": code_challenge}
    return JSONResponse(res)


@app.get("/")
async def callback(code: str, state: str):
    if state not in states:
        raise HTTPException(status_code=400, detail="invalid state")

    state_value = states[state]
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": state_value["redirect_uri"],
        "client_id": state_value["client_id"],
        "code_verifier": state_value["code_verifier"]
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(token_url, data=payload) as resp:
            if resp.ok:
                return await resp.json()
            else:
                raise HTTPException(status_code=400, detail="bad request")
