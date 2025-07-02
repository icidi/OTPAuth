from http import cookies
import logging
import urllib.parse as urlp

from server import HttpRequestHandler
import webpage

logger = logging.getLogger(__name__)

@HttpRequestHandler.registerPath("/tools")
def handleDirect(req: HttpRequestHandler, method="GET"):

    if method == "GET":
        req.setResponse(200, True)
        req.wfile.write(webpage.tools)
    else:
        req.setResponse(400)


@HttpRequestHandler.registerPath("/portal", "/portal/")
def handlePortal(req: HttpRequestHandler, method="GET"):

    if method == "GET":
        req.setResponse(200, True)
        req.wfile.write(webpage.loginSuccessful)
    else:
        req.setResponse(400)


@HttpRequestHandler.registerPath("/portal/login")
def handleLogin(req: HttpRequestHandler, method="GET", isValidSession=True):

    if method =="GET":
        req.setResponse(200, True)
        if isValidSession:
            req.wfile.write(webpage.loginSuccessful)
        else:
            req.wfile.write(webpage.login)
    
    elif method == "POST":    
        contentLength = int(req.getHeader("Content-Length", "0"))
        if contentLength <= 0:
            req.setResponse(400)
            return

        postData = req.rfile.read(contentLength)
        postData = postData.decode("utf-8")
        postData = urlp.parse_qs(postData)
        try:
            authUsername = postData["username"][0]
            authMethod = postData["method"][0]
            authSecret = postData["secret"][0]
        except KeyError:
            req.setResponse(400)
            return

        if req.users.auth(authUsername, authSecret, req.config.getConfigItem("otpwindow"), authMethod):
            newSession = req.sessions.new(authUsername)

            newCookie = cookies.SimpleCookie()
            # make a copy so that changes (i.e. pop() ) made to newCookieDict will not affect the original config buffer
            # there is no nested dict inside the cookie section of the config, so shallow copy is enough
            newCookieDict = req.config.getCookie().copy()
            newCookieName = newCookieDict["name"]
            newCookieDict.pop("name")

            newCookie[newCookieName] = newSession
            for k in newCookieDict.keys():
                newCookie[newCookieName][k] = newCookieDict[k]
            newCookie[newCookieName]["domain"] = req.config.getDomain()
            newCookie[newCookieName]["path"] = "/"

            # [1:] to remove leading space
            newCookieStr = newCookie.output(header="")[1:]

            redirectUrl = urlp.parse_qs(urlp.urlsplit(req.path).query).get("r", None)
            if redirectUrl != None:
                req.send_response(303)
                # in case there are multiple Set-Cookie headers, use send_header instead of setResponse to send them respectively
                req.send_header("Set-Cookie", newCookieStr)
                req.send_header("Location", redirectUrl[0])
                req.end_headers()
            else:
                req.send_response(200)
                req.send_header("Set-Cookie", newCookieStr)
                req.send_header("Content-Type", "text/html; charset=utf-8")
                req.end_headers()
                req.wfile.write(webpage.loginSuccessful)
        
        else:
            host = req.getHeader("X-Forwarded-Host")
            if host == None:
                host = req.getHeader("Host", "")
            ip = req.getHeader("X-Forwarded-For")
            if ip == None:
                ip = req.client_address[0]
            req.sessions.addBlacklist(ip, host, req.config.getConfigItem("attempt"), req.config.getConfigItem("findtime"), req.config.getConfigItem("bantime"))
            if req.sessions.isBanned(ip, host):
                req.setResponse(403, True)
                req.wfile.write(webpage.forbidden)
            else:
                req.setResponse(401, True)
                req.wfile.write(webpage.loginFailed)

    else:
        req.setResponse(400)

