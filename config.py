import json
import logging

logging.basicConfig(format="%(asctime)s: %(levelname)-8s %(message)s")
logger = logging.getLogger(__name__)

class Config:
    
    def __init__(self, filepath):

        useDefault = False

        try:
            f = open(filepath)
        except IOError as e:
            logger.error("Unable to open %s: %s", e.filename, e.strerror)
            logger.warning("Default values will be used")
            useDefault = True
        else:
            try:
                self.buffer = json.load(f)
            except json.JSONDecodeError as e:
                logger.error("JSON parsing error %s in %s", e.args, filepath)
                logger.warning("Default values will be used")
                useDefault = True
            finally:
                f.close()

        if useDefault:
            self.buffer = {} # TODO merge defaults with read config
        
        rootLogger = logging.getLogger()
        logLevel = self.buffer.get("loglevel", "INFO").upper()
        rootLogger.setLevel(getattr(logging, logLevel))


    def getDomain(self):

        domain = self.buffer.get("domain", "")
        if domain == "":
            logger.warning("Domain is not configured")
        return domain


    def getExternalPath(self):

        extpath = self.buffer.get("extpath", None)
        if extpath == None:
            logger.warning("External path is not configured")
            return "/otpauth"
        elif extpath == "/" or extpath == "":
            return ""
        else:
            newextpath = "/" + extpath.strip("/")
            if newextpath != extpath:
                logger.warning("External path: %s normalized to %s", extpath, newextpath)
            return newextpath


    def getCookie(self, keys=[]):

        cookie = self.buffer.get("cookie", {})
        if cookie == {}:
            logger.warning("Cookie is not configured")

        defaults = {"name": "otpauthsession", "max-age": 86400, "httponly": True, "secure": True, "samesite": "lax"}

        if keys == []:
            keys = defaults.keys()

        for k in keys:
            if type(cookie.get(k, None)) != type(defaults[k]):
                logger.warning("Invalid cookie.%s: %s. Using default: %s", k, cookie.get(k, None), defaults[k])
                cookie[k] = defaults[k]

        if len(keys) == 1:
            return cookie[keys[0]]
        else:
            return cookie


    def getConfigItem(self, key):

        itemValue = self.buffer.get(key, None)

        defaults = {"port": 9393, "inactivity": 900, "attempt": 3, "findtime": 300, "bantime": 900, "autoflush": 900, "otpwindow": 3}

        try:
            if itemValue > 0:
                return itemValue
        except:
            pass
        logger.warning("Invalid %s: %s. Using default: %s", key, itemValue, defaults[key])
        return defaults[key]

