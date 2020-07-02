import base64
import hashlib

from flask import Flask
from flask import request, make_response

app = Flask(__name__)


@app.route('/')
def index():

    print ('----------------------------')
    print (request.cookies)
    print ('----------------------------')
    
    if 'Authorization' in request.headers.keys():
        credentials = request.headers['Authorization']

        if credentials.find('Basic') == 0:
            authorization_list = credentials.split(' ')
            basic_credentials = authorization_list[1]
            basic_credentials_admin = base64.b64encode(b'admin:admin')

            if basic_credentials_admin == basic_credentials.encode('ascii'):
                return 'Authenticated, OK'

    # in case it is not authenticated, response a challenge
    response = make_response('Not Authenticated', 401)
    response.headers['WWW-Authenticate']  = 'Basic realm="simple"'
    return response


@app.route('/digest')
def digest_authen():
    user='admin'
    password='admin'
    realm='private'
    nonce='abc'
    algorithm='MD5'
    qop='auth'

    if 'Authorization' in request.headers.keys():
        credentials = request.headers['Authorization']

        scheme, digest_response = credentials.split(' ', 1)

        if scheme == 'Digest':

            nc = None
            response = None
            cnonce = None

            for item in digest_response.split(','):

                if '=' not in item:
                    continue
                key, value = item.split('=')
                key = key.strip()
                value = value.strip()

                if key == str("nc"):
                    print ("nc")
                    nc = value
                elif key == "response":
                    print ("response")
                    response = value.strip('\"')
                elif key == "cnonce":
                    print ("cnonce")
                    cnonce = value.strip('\"')

            #print (nc + ":" + response + ":" + cnonce)

            a1 = user + ":" + realm + ":" + password
            a1 = a1.encode('utf-8')
            ha1 = hashlib.md5(a1).hexdigest()

            a2 = 'GET' + ":" + "/digest"
            a2 =a2.encode('utf-8')
            ha2 = hashlib.md5(a2).hexdigest()

            res = ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2
            res = res.encode('utf-8')
            h_response = hashlib.md5(res).hexdigest()

            #print (h_response)

            if h_response == response:
                return 'Authenticated', 200

    response = make_response('Not Authenticated', 401)
    response.headers['WWW-Authenticate']  = 'Digest realm="%s", nonce="%s", algorithm="%s", qop="%s"' % (realm, nonce, algorithm, qop)
    return response

    
if __name__ == '__main__':
    app.debug=True
    app.run()