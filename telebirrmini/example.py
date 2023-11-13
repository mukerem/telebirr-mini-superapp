import os
from dotenv import load_dotenv
from telebirr import TelebirrMini
from utils import generate_unique

load_dotenv()

telebirr_app_secret = os.environ.get("TelebirrAppSecret")
telebirr_app_key = os.environ.get("TelebirrAppKey")
telebirr_short_code = os.environ.get("TelebirrShortCode")
telebirr_private_key = os.environ.get("TelebirrPrivateKey")
receiver_name = os.environ.get("TelebirrRecieverName")
telebirr_merchant_id = os.environ.get("TelebirrMerchantID")

tele = TelebirrMini(telebirr_app_secret, telebirr_app_key, telebirr_short_code, telebirr_private_key, receiver_name, telebirr_merchant_id)

response = tele.applyFabricToken()
print(response)

totalAmount = 10
nonce = generate_unique([], 32)
outTradeNo = generate_unique([], 32)
notifyUrl = "https://example.com/"
returnUrl = "https://example.com/"

response = tele.request(subject, totalAmount, nonce, outTradeNo, notifyUrl, returnUrl)
print(response)