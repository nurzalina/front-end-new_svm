import os

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT = os.getenv("TENANT")

REDIRECT_PATH = "/getAToken"  # redirect_uri set in AAD
PREFERRED_URL_SCHEME = 'https'

AUTHORITY = "https://login.microsoftonline.com/" + TENANT
SCOPE = ["User.ReadBasic.All"]
SESSION_TYPE = "filesystem"  # So token cache will be stored in server-side session