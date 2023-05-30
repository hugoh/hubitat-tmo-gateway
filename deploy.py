#!/usr/bin/env python
# pip3 install python-dotenv requests simplejson

# Adapted from https://github.com/syepes/Hubitat/blob/master/deploy.py

try:
    import argparse
    import http.cookiejar
    import os
    import pathlib

    import requests

    # dotenv
    from dotenv import find_dotenv, load_dotenv
except ModuleNotFoundError as e:
    print(
        "ModuleNotFoundError exception while attempting to import the needed modules: "
        + str(e)
    )
    exit(99)


def update(s, type, f, id):
    print("> Processing {} {}".format(type, id))
    response = s.get(url="{}/{}/ajax/code".format(he_url, type), params={"id": id})
    # print(response.text)

    # Check loging session
    if (
        "X-Frame-Options" in response.headers
        and response.headers["X-Frame-Options"] == "DENY"
    ):
        print(
            "Your HE Login Session has expired or been reseted, delete the file: .creds/cookie-jar.txt"
        )
        exit(1)

    if response.json()["status"] != "success":
        print("\tFailed downloading")
        return None

    version = response.json()["version"]
    print("\tCurrent version: " + str(version))

    print("\tUploading driver")
    sourceContents = f.read()

    response = s.post(
        url="{}/{}/ajax/update".format(he_url, type),
        data={"id": id, "version": version, "source": sourceContents},
    )
    # print(response.text)

    if response.json()["status"] == "success":
        print("\tSuccessfully uploaded")
    elif response.json()["status"] == "error":
        print("\tFailed uploading: " + response.json()["errorMessage"])
        return None
    else:
        print("\tFailed uploading: " + response.json())
        return None


def he_login(path):
    credentialStorageFolderPath = pathlib.Path(path, ".creds")
    cookieJarFilePath = pathlib.Path(credentialStorageFolderPath, "cookie-jar.txt")
    # print("str(cookieJarFilePath.resolve()): " + str(cookieJarFilePath.resolve()))

    session = requests.Session()
    cookieJarFilePath.resolve().parent.mkdir(parents=True, exist_ok=True)
    session.cookies = http.cookiejar.MozillaCookieJar(
        filename=str(cookieJarFilePath.resolve())
    )

    # Ensure that the cookie jar file exists and contains a working cookie to authenticate
    # into the Hubitat web interface
    if os.path.isfile(session.cookies.filename):
        session.cookies.load(ignore_discard=True)
    else:
        # Collect username and password from the user
        print("Hubitat username: ")
        hubitatUsername = input()
        print("Hubitat password: ")
        hubitatPassword = input()
        print("Entered " + hubitatUsername + " and " + hubitatPassword)

        session.post(
            he_url + "/login",
            data={
                "username": hubitatUsername,
                "password": hubitatPassword,
                "submit": "Login",
            },
        )
        session.cookies.save(ignore_discard=True)

    return session


parser = argparse.ArgumentParser()
parser.add_argument("type", help="Type of asset updated", choices=["app", "driver"])
parser.add_argument("file", help="File to upload", type=argparse.FileType("r"))
parser.add_argument("id", help="ID on HE")
args = parser.parse_args()

load_dotenv(find_dotenv(), verbose=True)

he_url = os.getenv("HE_URL")
if he_url is None:
    print("HE_URL is not defined in the .env file")
    exit(99)

print("Connecting to: " + he_url)
session = he_login(os.path.dirname(os.path.realpath(__file__)))

update(session, args.type, args.file, args.id)
