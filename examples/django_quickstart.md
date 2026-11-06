# Django quickstart

```bash
pip install "generateapikey[django]"      # + [drf] for Django REST Framework
```

```python
# myapp/models.py
from django.conf import settings
from django.db import models
from generateapikey.integrations.django import AbstractAPIKey


class APIKey(AbstractAPIKey):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_keys")
```

```bash
python manage.py makemigrations myapp && python manage.py migrate
```

```python
# myproject/auth.py
from django.conf import settings
from generateapikey.integrations.django import APIKeyAuth, model_lookup, touch_last_used
from myapp.models import APIKey

auth = APIKeyAuth(
    lookup=model_lookup(APIKey, select_related=("user",)),
    pepper=settings.API_KEY_PEPPER,  # from env, not in the DB
    prefix="sk",
    require_checksum=True,
    on_success=touch_last_used,
)
```

```python
# settings.py
GENERATEAPIKEY_AUTH = "myproject.auth.auth"
# optional, site-wide: sets request.api_key, rejects invalid keys
MIDDLEWARE += ["generateapikey.integrations.django.APIKeyMiddleware"]
# DRF
REST_FRAMEWORK = {"DEFAULT_AUTHENTICATION_CLASSES": ["generateapikey.integrations.drf.APIKeyAuthentication"]}
```

```python
# views.py
from django.http import JsonResponse
from generateapikey.integrations.django import api_key_required
from myproject.auth import auth


@api_key_required(auth)
def whoami(request):
    return JsonResponse({"user": request.api_key.user.username})


def create_key(request):  # behind your normal login
    obj, raw = APIKey.objects.create_key(pepper=settings.API_KEY_PEPPER, name="CLI", user=request.user)
    return JsonResponse({"api_key": raw, "hint": obj.hint})  # shown once


def rotate_key(request, pk):
    old = APIKey.objects.get(pk=pk, user=request.user)
    new, raw = old.rotate(pepper=settings.API_KEY_PEPPER, grace=timedelta(hours=24))
    return JsonResponse({"api_key": raw})  # old key keeps working for 24 h
```
