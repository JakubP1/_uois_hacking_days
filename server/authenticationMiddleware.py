import os

from starlette.authentication import (
    AuthCredentials, AuthenticationBackend, AuthenticationError
)
from starlette.middleware.authentication import AuthenticationMiddleware
import aiohttp
import jwt
import json
import logging

JWTPUBLICKEY = "http://localhost:8000/oauth/publickey"
JWTRESOLVEUSERPATH = "http://localhost:8000/oauth/userinfo"

class BasicAuthBackend(AuthenticationBackend):
    def __init__(self, 
        JWTPUBLICKEY = JWTPUBLICKEY,
        JWTRESOLVEUSERPATH = JWTRESOLVEUSERPATH
        ) -> None:

        # super().__init__()
        self.publickey = None
        self.JWTPUBLICKEY = JWTPUBLICKEY
        self.JWTRESOLVEUSERPATH = JWTRESOLVEUSERPATH

    async def getPublicKey(self):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.JWTPUBLICKEY) as resp:
                    if resp.status != 200:
                        logging.error(f"Failed to retrieve public key: HTTP status {resp.status}")
                        raise AuthenticationError("Public key not available")

                    # publickey = await resp.read()
                    publickey = await resp.text()
            except Exception as e:
                logging.error(f"Exception while retrieving public key: {str(e)}")
                raise AuthenticationError(f"Failed to retrieve public key: {str(e)}")

        self.publickey = publickey.replace('"', '').replace('\\n', '\n').encode()
        logging.info(f"Got public key successfully: {self.publickey}")
        return self.publickey

    async def authenticate(self, conn):
        #print("# BEGIN #######################################")
        logging.info("Authenticating")
        client = conn.client
        headers = conn.headers
        cookies = conn.cookies
        url = conn.url
        base_url = conn.base_url
        uri = url.path
        conn.url.path
        logging.info(f'{base_url} {client}, {headers}, {cookies}')
        logging.info(f'{uri}')
        print(f'{base_url} {client}, {headers}, {cookies}')
        print(f'{uri}')        
        
        # 1. ziskat jwt (cookies authorization nebo header Authorization: Bearer )
        jwtsource = cookies.get("authorization", None)
        if jwtsource is None:
            authorization_header = headers.get("Authorization", None)
            if authorization_header and authorization_header.startswith("Bearer "): # Header can be malformed
                [_, jwtsource] = authorization_header.split("Bearer ")
            else:
                # Unathorized access
                logging.warning("Missing or invalid authorization header")
                raise AuthenticationError("Missing or invalid authorization header")

        # Each JWT is made up of three segments, each separated by a dot (.)
        if not jwtsource or not jwtsource.count(".") == 2:
            logging.warning("Invalid JWT token format")
            raise AuthenticationError("Invalid JWT token")

        logging.info("JWT token retrieved")

        # 2. ziskat verejny klic (async request to authority)
        publickey = self.publickey
        if publickey is None:
            publickey = await self.getPublicKey()
        
        # 3. overit jwt (lokalne)
        for i in range(2):
            try:
                jwtdecoded = jwt.decode(jwt=jwtsource, key=publickey, algorithms=["RS256"])
                logging.info("JWT token successfully decoded")
                break
            except jwt.InvalidSignatureError as e:
                logging.error("Invalid JWT signature, attempting to refresh public key")
                # je mozne ulozit key do cache a pri chybe si key ziskat (obnovit) a provest revalidaci
                print(e)
            if (i == 1):
                # klic byl aktualizovan a presto doslo k vyjimce
                raise AuthenticationError("Invalid signature")
            
            # aktualizace klice, predchozi selhal
            publickey = await self.getPublicKey()
            #print('publickey refreshed', publickey)
            logging.info("Public key refreshed")
        
        print('got jwtdecoded', jwtdecoded)

        # 3A. pokud jwt obsahuje user.id, vzit jej primo
        user_id = jwtdecoded.get("user_id", None)
        print("some user?", user_id)

        # 4. pouzit jwt jako parametr pro identifikaci uzivatele u autority
        if user_id is None:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {jwtdecoded['access_token']}"}
                async with session.get(self.JWTRESOLVEUSERPATH, headers=headers) as resp:
                    if resp.status != 200:
                        logging.error(f"Failed to resolve user: HTTP status {resp.status}")
                        raise AuthenticationError("Failed to resolve user")
                    userinfo = await resp.json()
                    user_id = userinfo("user", {}).get("id", None)
                    print("got userinfo", userinfo)
                    print("got userinfo", userinfo["user"])

        demouser = os.getenv("DEMOUSER", '{"id": "2d9dc5ca-a4a2-11ed-b9df-0242ac120003", "name": "John", "surname": "Newbie"}')
        user = json.loads(demouser)
        if user_id is None:
            user["id"] = user_id
            
        #print("# SUCCESS #######################################")
        logging.info("Authentication successful")
        return AuthCredentials(["authenticated"]), user
    
from starlette.requests import HTTPConnection
from starlette.responses import PlainTextResponse, Response, RedirectResponse

class BasicAuthenticationMiddleware302(AuthenticationMiddleware):
    @staticmethod
    def default_on_error(conn: HTTPConnection, exc: Exception) -> Response:
        where = conn.url.path
        logging.error(f"Authentication error on {where}: {str(exc)}")
        result = RedirectResponse(f"/oauth/login2?redirect_uri={where}", status_code=302)
        result.delete_cookie("authorization")
        return result

class BasicAuthenticationMiddleware404(AuthenticationMiddleware):
    @staticmethod
    def default_on_error(conn: HTTPConnection, exc: Exception) -> Response:
        where = conn.url.path
        logging.error(f"Authentication error on {where}: {str(exc)}")
        result = PlainTextResponse(f"Unauthorized for {where}", status_code=404)
        result.delete_cookie("authorization")
        return result
