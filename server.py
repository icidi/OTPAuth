from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import urllib.parse as urlp

# import to declare class variables only
from config import Config
from usermanager import UserManager
from sessionmanager import SessionManager

import timer
import webpage

logger = logging.getLogger(__name__)

class HttpRequestHandler(BaseHTTPRequestHandler):

    config: Config = None
    users: UserManager = None
    sessions: SessionManager = None

    lut = {}


    @staticmethod
    def initialize(config, users, sessions):

        HttpRequestHandler.config = config
        HttpRequestHandler.users = users
        HttpRequestHandler.sessions = sessions

    
    def setResponse(self, code=200, html=False, headers={}):

        self.send_response(code)
        if html:
            self.send_header("Content-Type", "text/html; charset=utf-8")
        for k in headers.keys():
            self.send_header(k, headers[k])
        self.end_headers()


    def getHeader(self, key, default=None):

        try:
            return self.headers[ list(self.headers.keys())[ list(k.lower() for k in self.headers.keys()).index(key.lower()) ] ]
        except ValueError:
            return default


    def handleRequest(self, method="GET"):

        logger.debug("Received request headers:\n%sEnd of request headers", self.headers)

        # check if host is valid
        host = self.getHeader("X-Forwarded-Host")
        if host == None:
            host = self.getHeader("Host", "")
        self.host = host
        domain = host.split(":", 1)[0]
        if domain == "" or not domain.endswith(self.config.getDomain()):
            self.setResponse(400)
            logger.warning("Received header X-Forwarded-Host/Host: %s does not match configured domain", domain)
            return

        # check if request path is valid
        externalPath = self.config.getExternalPath()
        requestPath = self.users.sanitizePath(urlp.urlsplit(self.path).path)
        if requestPath != "/otpauth/forwardauth" and not requestPath.startswith(externalPath):
            self.setResponse(400)
            logger.warning("Request path: %s does not match configured external path", requestPath)
            return

        # get session from cookie
        c = self.getHeader("Cookie")
        # session = None
        # if c != None:
        c = cookies.SimpleCookie(c)
        session = c.get(self.config.getCookie(["name"]), None)
        if session != None:
            session = session.value
        self.session = session
            
        path = self.getHeader("X-Forwarded-Uri")

        # check if session is valid
        if self.sessions.check(session, self.config.getConfigItem("inactivity")):
            
            path = urlp.urlsplit(path).path # if path == None, return = b""
            # if no X-Forwarded-Uri header, then it is not a ForwardAuth request
            # assuming it is a direct request to otpauth, e.g. accessing the login page directly
            # access to <externalPath>/portal/* is always allowed
            bypassAcl = False
            direct = False
            if path == b"":
                direct = True
                path = requestPath
                bypassAcl = path == (externalPath + "/portal") or path.startswith(externalPath + "/portal/")
            
            if bypassAcl:
                self.handlePath(path.replace(externalPath, "", 1), method)
            elif self.users.checkAcl(self.sessions.getUsername(session), path, not direct):
                if requestPath == "/otpauth/forwardauth":
                    self.setResponse(200)
                else:
                    # direct requests that pass acl and not begin with "/portal" goes here
                    self.handlePath(path.replace(externalPath, "", 1), method)
            elif not direct:
                self.setResponse(403, True)
                self.wfile.write(webpage.forbidden)
            else:
                self.setResponse(404, True)
                self.wfile.write(webpage.notFound)

            return

        # get client ip
        ip = self.getHeader("X-Forwarded-For")
        if ip == None:
            ip = self.client_address[0]
        self.ip = ip
        
        forwardedMethod = self.getHeader("X-Forwarded-Method")

        # log some additional info for requests without a valid session
        # only log when level = INFO since DEBUG logs elsewhere have already covered this log
        if logger.getEffectiveLevel() == logging.INFO:
            if path != None:
                logging.info("%s ForwardAuth %s %s %s", ip, forwardedMethod, host, path)
            else:
                logging.info("%s Direct %s %s %s", ip, method, host, self.path)

        query = urlp.parse_qs(urlp.urlsplit(self.path).query)
        # do not redirect if it is a silent request
        silent = query.get("silent", None)
        if silent != None and silent[0] == "1":
            self.setResponse(401)
            return

        # check if client is banned
        if self.sessions.isBanned(ip, host):
            self.setResponse(403, True)
            self.wfile.write(webpage.forbidden)
            return
        
        # if accessing the login page directly
        if requestPath == externalPath + "/portal/login":
            self.handlePath("/portal/login", method, False)
            return

        # generate the redirection URL which is used after successful login
        # in this order: "r=" query in the request URL, Referer header, <X-Forwarded-Host + X-Forwarded-Uri>, None
        redirection = query.get("r", None)
        if redirection != None:
            redirection = redirection[0]
        else:
            redirection = self.getHeader("Referer")
        if redirection == None:
            proto = self.getHeader("X-Forwarded-Proto")
            forwardedHost = self.getHeader("X-Forwarded-Host")
            # path is retrieved before checking if session is valid
            # after successful login, only redirect if it is a ForwardAuth request, so host and path do not fallback
            if path != None and proto != None and forwardedHost != None:
                redirection = proto + "://" + forwardedHost + path

        # generate the URL to login page
        try:
            externalUrl = query["external_url"][0]
        except KeyError:
            proto = self.getHeader("X-Forwarded-Proto")
            if proto != None:
                proto = proto + "://"
            else:
                proto = "//"
            externalUrl = proto + host + externalPath

        loginUrl = externalUrl + "/portal/login"

        if redirection != None:
            loginUrl = loginUrl + "?r=" + redirection
        
        # redirect to login page
        # forwardedMethod = self.getHeader("X-Forwarded-Method")
        if forwardedMethod == "GET" or (forwardedMethod == None and method == "GET"):
            self.setResponse(302, False, {"Location": loginUrl})
        else:
            self.setResponse(303, False, {"Location": loginUrl})


    @staticmethod
    def registerPath(*paths):

        def decorator(func):

            for p in paths:
                HttpRequestHandler.lut[p] = func
            return func

        return decorator


    def handlePath(self, path, *args, **kwargs):

        handler = self.lut.get(path, None)
        if handler != None:
            handler(self, *args, **kwargs)
        else:
            self.setResponse(404, True)
            self.wfile.write(webpage.notFound)


    def do_GET(self):

        self.handleRequest("GET")
        

    def do_POST(self):

        self.handleRequest("POST")
    

    def log_message(self, format, *args):

        logger.debug("%s " + format, self.client_address, *args)



class Server:

    def __init__(self, config, users, sessions):

        self.config = config
        self.users = users
        self.sessions = sessions

        HttpRequestHandler.initialize(self.config, self.users, self.sessions)


    def run(self):

        autoFlushInterval = self.config.getConfigItem("autoflush")
        timerFlushSession = timer.Timer(autoFlushInterval, self.sessions.flush, self.config.getConfigItem("inactivity"))
        timerFlushSession.start()
        timerFlushBlacklist = timer.Timer(autoFlushInterval, self.sessions.flushBlacklist, self.config.getConfigItem("findtime"))
        timerFlushBlacklist.start()

        port = self.config.getConfigItem("port")
        httpd = HTTPServer(("", port), HttpRequestHandler)
        logger.info("Server listening on %s", httpd.server_address)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
            timerFlushSession.stop()
            timerFlushBlacklist.stop()

