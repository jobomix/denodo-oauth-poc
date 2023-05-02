import string

import pkce
import random
import aiohttp

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse

app = FastAPI()
states = {}

authorize_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"


@app.get("/authorize")
async def authorize_url(client_id: str,
                        aad=authorize_url,
                        response_type="code",
                        scope="openid https://positdev.sharepoint.com/AllSites.Write",
                        redirect_uri="https://denodo.positdev.co.uk"):
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

    del states[state]

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": state_value["redirect_uri"],
        "client_id": state_value["client_id"],
        "code_verifier": state_value["code_verifier"]
    }

    def html(token, access_token=""):
        return f"""
         <html>
         <head>
         <title>Denodo access</title>
         </head>
         <body>
             <h2>Denodo ODBC connection</h2>
             <p>Copy paste the following code snippet to create your Denodo ODBC connection in R studio</p>
             <textarea cols="120" rows="20">
                library(DBI)
                con <- dbConnect(odbc::odbc(), "Denodo_Oauth_DSN",
                UseOAuth2 = 1,
                AccessToken = "{token}", 
                timeout = 10)
                
                sharePointAccessToken="{access_token}"
             </textarea>
         </body>
         </html>
        """

    async with aiohttp.ClientSession() as session:
        async with session.post(token_url, data=payload) as resp:
            if resp.ok:
                tkn_json = await resp.json()
                id_token = tkn_json["id_token"]
                sp_access_token = tkn_json["access_token"]
                return HTMLResponse(content=html(id_token,
                                                 access_token=sp_access_token))
            else:
                print(resp)
                raise HTTPException(status_code=400, detail="bad request")
