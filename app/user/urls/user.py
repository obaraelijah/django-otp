from django.urls import include, path
from rest_framework.routers import DefaultRouter


app_name = 'user'

router = DefaultRouter()


urlpatterns = [
    path('', include(router.urls)),
]