# Download the helper library from https://www.twilio.com/docs/python/install
from twilio.rest import Client


# Your Account Sid and Auth Token from twilio.com/console
account_sid = 'AC1d5763ab613e5432e825c7b89585291f'
auth_token = '66f3cd11b5029b5fe1236f69ff3a7cf7'
client = Client(account_sid, auth_token)

message = client.messages \
    .create(
         body='Someone wants to get a meal with you!',
         from_='+18125671658',
         to='+17073865192'
     )

print(message.sid)