import base64
import fnmatch
import hashlib
import json
import logging
import pathlib
import sys
import time

from mintotp.mintotp import hotp

logger = logging.getLogger(__name__)

class UserManager:

    def __init__(self, filepath):

        try:
            f = open(filepath)
        except IOError as e:
            logger.critical("Unable to open %s: %s", e.filename, e.strerror)
            sys.exit(1)
        else:
            try:
                self.users = json.load(f)
            except json.JSONDecodeError as e:
                logger.critical("JSON parsing error %s in %s", e.args, filepath)
                sys.exit(1)
            finally:
                f.close()

        if "users" in self.users and len(self.users["users"]) > 0:
            self.users = self.users["users"]
            self.lastTotpCounter = dict.fromkeys(self.users.keys(), 0)
        else:
            logger.critical("No user found in %s", filepath)
            sys.exit(1)


    def auth(self, username, secret, otpwindow=3, method="totp"):

        if username in self.users and not self.users[username].get("disabled", False) and method in ("totp", "password") and method in self.users[username]:
            if method == "totp":
                result = self.authTotp(username, secret, otpwindow)
            elif method == "password":
                result = self.authPassword(username, secret)
            
            if result:
                logger.info("Successful %s authentication for user: %s", method, username)
            else:
                logger.info("Failed %s authentication for user: %s", method, username)
            return result
        else:
            if username not in self.users:
                reason = "User not exist"
            elif self.users[username].get("disabled", False):
                reason = "Disabled user"
            else:
                reason = "Unsupported method: " + method

            logger.info("Failed authentication for user: %s. Reason: %s", username, reason)
            return False


    def authPassword(self, username, secret):

        if self.users[username]["password"].get("algorithm") != None:
            algorithm = self.users[username]["password"]["algorithm"]
            logger.debug("Started password authentication for user: %s", username)
            try:
                h = hashlib.pbkdf2_hmac(algorithm, bytes(secret, "utf-8"), bytes(username, "utf-8"), 600000)
            except ValueError as e:
                logger.warning("%s algorithm %s", e, algorithm)
            else:
                return h.hex() == self.users[username]["password"].get("hash")

        return False


    def authTotp(self, username, secret, otpwindow):

        digits = self.users[username]["totp"].get("digits", 6)
        if digits < 4 or digits > 10:
            logger.warning("Invalid TOTP digits: %d. Using default: 6", digits)
            digits = 6
        
        algorithm = self.users[username]["totp"].get("algorithm", "sha1")
        key = self.users[username]["totp"].get("key", None)
        
        if otpwindow < 0 or otpwindow > 10:
            logger.warning("Invalid otpwindow: %d. Using default: 3", otpwindow)
            otpwindow = 3
        
        if key != None:
            counter = int(time.time() / 30)
            counterList = [c for c in range(counter - otpwindow, counter + otpwindow + 1) if c > self.lastTotpCounter[username]]

            if len(counterList) == 0:
                logger.info("No TOTP can be generated due to empty counter list")
                return False

            totpList = []
            try:
                for c in counterList:
                    totpList.append(hotp(key, c, digits, algorithm))
            except base64.binascii.Error as e:
                logger.warning("%s in key", e)
            except ValueError as e:
                logger.warning("%s algorithm %s", e, algorithm)
            else:
                try:
                    i = totpList.index(secret)
                except ValueError:
                    pass
                else:
                    self.lastTotpCounter[username] = counterList[i]
                    return True

        return False


    def checkAcl(self, username, path, needSanitize=True):
        
        acl = self.users[username].get("acl")

        if acl == None or len(acl) == 0:
            logger.debug("User: %s ACL not configured", username)
            logger.debug("Allowed user: %s access to %s", username, path)
            return True

        if needSanitize:
            path = self.sanitizePath(path)

        for a in acl:
            deny = a[0] == "!"
            if deny:
                a = a[1:]

            if fnmatch.fnmatch(path.lower(), a):
                if deny:
                    logger.info("Matched ACL rule: !%s", a)
                    logger.info("Denied user: %s access to %s", username, path)
                else:
                    logger.debug("Matched ACL rule: %s", a)
                    logger.debug("Allowed user: %s access to %s", username, path)
                return not deny

        logger.info("No ACL rule matched")
        logger.info("Denied user: %s access to %s", username, path)
        return False


    def sanitizePath(self, path):

        logger.debug("Original path: %s", path)

        path = path.replace("\\", "/")

        if path[0] != "/":
            path = "/" + path

        while path.find("//") >= 0:
            path = path.replace("//", "/")

        # prepend some non-existent path to the path to prevent resolving into the actual filesystem
        path = "/$[NONEXISTENT]$" + path

        sanitized = str(pathlib.PosixPath(path).resolve(strict=False))

        if sanitized[-1] != "/" and (path.endswith("/") or path.endswith("/.") or path.endswith("/..")):
            sanitized = sanitized + "/"

        if sanitized.startswith("/$[NONEXISTENT]$"):
            sanitized = sanitized[len("/$[NONEXISTENT]$"):]

        logger.debug("Sanitized path: %s", sanitized)

        return sanitized

