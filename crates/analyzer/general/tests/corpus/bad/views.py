# EXPECT: gen_web_csrf_disabled
# EXPECT: gen_web_ssrf
from django.views.decorators.csrf import csrf_exempt
import requests

@csrf_exempt
def pay(request):
    return requests.post(request.POST["callback"], data={})
