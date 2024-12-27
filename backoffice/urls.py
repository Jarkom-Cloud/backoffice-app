from django.urls import path
from backoffice.views import (
    register,
    login,
    get_sales_date,
    logout,
    register_page,
    login_page,
    protected_page,
    get_sales_detail
)

app_name = "backoffice"

urlpatterns = [
    path("register/", register, name="register"),
    path("login/", login, name="login"),
    path("resource_sales/<str:date>/", get_sales_date, name="resource"),
    path("logout/", logout, name="logout"),
    path("register-page/", register_page, name="register_page"),
    path("login-page/", login_page, name="login_page"),
    path("main/", protected_page, name="main"),
    path("sales-detail/<int:id>/", get_sales_detail, name="get_sales_detail"),
]
