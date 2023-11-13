import hmac
import hashlib
import json
import urllib.parse
import base64
import datetime
import json
import math
import requests
import rsa
import six
import time

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from hashlib import sha256
from urllib3.exceptions import *


class DecryptByPublicKey(object):
    """
         the modulus factor is generated first 
         the rsa public key is then generated 
         then use the rsa public key to decrypt the incoming encryption str
    """
    def __init__(self, publicKey):
        public_key =  RSA.import_key(base64.urlsafe_b64decode(publicKey))
        self._modulus = public_key.n   #  the modulus 
        self._exponent = public_key.e  #  factor 
        try:
            rsa_pubkey = rsa.PublicKey(self._modulus, self._exponent)
            self._pub_rsa_key = rsa_pubkey.save_pkcs1() #  using publickey ( modulus, factor ) calculate a public key 
        except Exception as e:
            raise TypeError(e)

    def decrypt(self, b64decoded_encrypt_text) ->str:
        """
        decrypt msg by public key
        """
        public_key = rsa.PublicKey.load_pkcs1(self._pub_rsa_key)
        encrypted = rsa.transform.bytes2int(b64decoded_encrypt_text)
        decrypted = rsa.core.decrypt_int(encrypted, public_key.e, public_key.n)

        decrypted_bytes = rsa.transform.int2bytes(decrypted)
        if len(decrypted_bytes) > 0 and list(six.iterbytes(decrypted_bytes))[0] == 1:
            try:
                raw_info = decrypted_bytes[decrypted_bytes.find(b'\x00')+1:]
            except Exception as e:
                raise TypeError(e)
        else:
            raw_info = decrypted_bytes
        return raw_info.decode("utf-8")


class TelebirrMini:
    def __init__(self, app_secret, app_key, short_code, private_key, name, merchant_id) -> None:
        self.app_secret = app_secret
        self.app_key = app_key
        self.short_code = short_code
        self.private_key = private_key
        self.name = name
        self.merchant_id = merchant_id
        self.url = "https://196.188.120.3:38443/apiaccess/payment/gateway"
    
    def apply_fabric_token(self):
        url =  f"{self.url}/payment/v1/token"
        body = {
            "appSecret" : self.app_secret
        }
        headers = {
            "X-APP-Key": self.app_key
        }
        response = requests.post(url=url, json=body, headers=headers, verify=False)
        return response.json()
    

def hmacDigest(data, key):
    keyEncoded = key.encode()
    dataEncoded = data.encode()

    h = hmac.new(keyEncoded, dataEncoded, hashlib.sha256)

    return h.hexdigest()


def generateSignature(apiSecret, method, uri, timestamp, body):
    url = urllib.parse.urlparse(uri)
    path = url.path

    if (url.query):
        path = path + "?" + url.query

    methodUpperCase = method.upper()
    data = methodUpperCase + path + str(timestamp)

    if (body):
        data += json.dumps(body, separators=(',',':'))

    return hmacDigest(data, apiSecret)


expectedSignature = "56ac656c7f932c5b775be28949e90af9a2356eae2826539f10ab6526a0eec762"
generatedSignature = generateSignature(
    "SECRET",
    "POST",
    "http://demo.example.com/webhook?a=1",
     1563276169752,
    {"a": 1}
)

    def request_create_order(self, nonce_str, ):
        url = f"{self.url}/payment/v1/merchant/preOrder/"
        token = self.apply_fabric_token().get("token")
        timeoutExpress = 5
        timestamp = time.time()
        signature = utils.sign(payload, self.private_key)

        body = {
            "timestamp": str(timestamp),
            "method": "payment.preorder",
            "nonce_str": nonce_str,
            "sign_type": "SHA256WithRSA",
            "sign": "BC4EE8D710BAC6A7E33DE4511A1CE7723024615EEF491B80DEF7DC743D4DADBE",
            "version": "1.0",
            "biz_content": {
                "notify_url": "http://test.payment.com/notify",
                "redirect_url": "http://test.payment.com/redirect",
                "appid": "12312b84664d44679693855d82a291",
                "merch_code": "200001",
                "merch_order_id": "201907161732001",
                "trade_type": "InApp",
                "title": "GameRecharge",
                "total_amount": "2000",
                "trans_currency": "USD",
                "timeout_express": "120m",
                "business_type": "BuyGoods",
                "callback_info": "string"
            }
        }

