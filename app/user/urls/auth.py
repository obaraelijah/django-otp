from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

app_name = "auth"
router = DefaultRouter()

urlpatterns = [
    path("", include(router.urls)),
]
