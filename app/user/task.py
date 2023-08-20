from core.celery import APP
from .utils import send_sms
#celery for  asynchronous processing, to send phone notifications asynchronously.


@APP.task()
def send_phone_notification(user_data):
    send_sms(user_data['message'], user_data['phone'])
    