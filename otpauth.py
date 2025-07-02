#!/usr/bin/env python3

import argparse
import logging

from config import Config
from usermanager import UserManager
from sessionmanager import SessionManager
from server import Server
import handler


__version__ = "0.0.3"

logger = logging.getLogger(__name__)

def main():

    parser = argparse.ArgumentParser(description="OTP Authentication Backend")
    parser.add_argument("--config", dest="configFilepath", metavar="configFilepath", default="config.json", help="path to configuration file")
    parser.add_argument("--user", dest="userFilepath", metavar="userFilepath", default="users.json", help="path to user database file")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()

    print("otpauth version", __version__)
    print("Using configuration file:", args.configFilepath)
    print("Using user database file:", args.userFilepath)

    config = Config(args.configFilepath)
    users = UserManager(args.userFilepath)

    logger.info("Finished reading configuration files")

    sessions = SessionManager()


    server = Server(config, users, sessions)
    server.run()


if __name__ == '__main__':
    main()

