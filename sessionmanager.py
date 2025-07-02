import logging
import secrets
import time

logger = logging.getLogger(__name__)

class SessionManager:

    def __init__(self):
        self.sessions = {}
        self.blacklist = {}


    def new(self, username):

        session = secrets.token_urlsafe(32)
        lastSeen = int(time.time())

        self.sessions[session] = {"username": username, "lastSeen": lastSeen}

        logger.info("New session %s created for user: %s", session, username)

        return session
        
    
    def delete(self, session):

        try:
            self.sessions.pop(session)
        except KeyError:
            logger.info("Session %s does not exist", session)
        else:
            logger.info("Session %s is successfully deleted", session)

        return True


    def check(self, session, inactivity, update=True):

        now = int(time.time())

        if session in self.sessions.keys() and now - self.sessions[session]["lastSeen"] < inactivity:
            if update:
                self.sessions[session]["lastSeen"] = now
                logger.debug("Session %s is validated and updated", session)
            else:
                logger.debug("Session %s is validated", session)
            return True
        else:
            logger.info("Session %s does not exist or has expired", session)
            return False


    def getUsername(self, session):

        return self.sessions[session]["username"]


    def flush(self, inactivity):

        num = len(self.sessions)
        now = int(time.time())
        for k in list(self.sessions.keys()):
            if now - self.sessions[k]["lastSeen"] >= inactivity:
                self.sessions.pop(k)

        expired = num - len(self.sessions)
        if expired > 0:
            logger.info("%d expired sessions flushed, %d active sessions remaining", expired, len(self.sessions))
        return True


    def addBlacklist(self, ip, host, attempt, findtime, bantime):

        if (ip, host) not in self.blacklist.keys():
            self.blacklist[ip, host] = {"failures": [], "bannedUntil": 0}

        now = int(time.time())
        self.blacklist[ip, host]["failures"].append(now)

        if len(self.blacklist[ip, host]["failures"]) >= attempt:
            if self.blacklist[ip, host]["failures"][ -attempt] >= now - findtime:
                self.blacklist[ip, host]["bannedUntil"] = now + bantime
                logger.info("%s accessing %s failed to authenticate %d times in %ds", ip, host, attempt,  now - self.blacklist[ip, host]["failures"][ -attempt])
                logger.info("%s accessing %s is banned for %ds", ip, host, bantime)
                return True
        return False
        

    def isBanned(self, ip, host):

        if (ip, host) in self.blacklist.keys():
            if self.blacklist[ip, host]["bannedUntil"] >= int(time.time()):
                logger.debug("%s accessing %s is banned", ip, host)
                return True
        
        return False


    def deleteBlacklist(self, ip, host):

        try:
            self.blacklist.pop( (ip, host) )
        except KeyError:
            logger.info("%s accessing %s is not in blacklist", ip, host)
        else:
            logger.info("%s accessing %s is removed from blacklist", ip, host)

        return True


    def unban(self, ip, host):

        if (ip, host) in self.blacklist.keys():
            now = int(time.time())
            if self.blacklist[ip, host]["bannedUntil"] > now:
                self.blacklist[ip, host]["bannedUntil"] = now
                logger.info("%s accessing %s is unbanned", ip, host)
            else:
                logger.info("%s accessing %s is not banned", ip, host)
        else:
            logger.info("%s accessing %s is not in blacklist", ip, host)

        return True

    
    def flushBlacklist(self, findtime):

        now = int(time.time())
        flushed = 0
        for k in list(self.blacklist.keys()):
            if self.blacklist[k]["bannedUntil"] < now and ( len(self.blacklist[k]["failures"]) == 0 or self.blacklist[k]["failures"][-1] < now - findtime):
                self.blacklist.pop(k)
                flushed = flushed + 1
            else:
                pos = 0
                while pos < len(self.blacklist[k]["failures"]) and self.blacklist[k]["failures"][pos] < now - findtime:
                    pos = pos + 1
                self.blacklist[k]["failures"] = self.blacklist[k]["failures"][pos:]
                flushed = flushed + pos

        if flushed > 0:
            logger.info("Blacklist flushed")
        return True

