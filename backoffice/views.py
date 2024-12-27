import bcrypt
import psycopg2
from django.http import JsonResponse
from connect import connect_to_postgres
import secrets
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
import json
from datetime import datetime

def register_page(request):
    return render(request, "register.html")

def login_page(request):
    return render(request, "login.html")

def protected_page(request):
    return render(request, "main.html")

@csrf_exempt
def register(request):
    if request.method == "POST":
        data = json.loads(request.body)
        username = data.get("username")
        password = data.get("password")
        print(username, password)
        if not username or not password:
            return JsonResponse(
                {"error": "Username dan password harus terisi"}, status=400
            )
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        connection = connect_to_postgres()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO OfficeUser (username, password_hash) VALUES (%s, %s)",
                    (username, hashed_password),
                )
                connection.commit()
                return JsonResponse(
                    {"message": "User berhasil didaftarkan"}, status=201
                )
        except psycopg2.errors.UniqueViolation:
            return JsonResponse({"error": "Username sudah ada di database"}, status=400)
        except Exception as e:
            print(f"Error during registration: {e}")
            return JsonResponse({"error": "Server error"}, status=500)
        finally:
            connection.close()
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return JsonResponse(
                {"error": "Username dan password harus terisi"}, status=400
            )
        connection = connect_to_postgres()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id, password_hash FROM OfficeUser WHERE username = %s",
                    (username,),
                )
                result = cursor.fetchone()
                if not result:
                    return JsonResponse({"error": "Invalid username or password"}, status=401)
                user_id, stored_hash = result
                if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    return JsonResponse({"error": "Invalid username or password"}, status=401)
                token = secrets.token_urlsafe(32)
                cursor.execute(
                    "INSERT INTO AuthOfficeToken (user_id, token) VALUES (%s, %s)",
                    (user_id, token)
                )
                connection.commit()
                return JsonResponse({"token": token}, status=200)
        except Exception as e:
            print(f"Error during login: {e}")
            return JsonResponse({"error": "Server error"}, status=500)
        finally:
            connection.close()
    return JsonResponse({"error": "Invalid request method"}, status=405)

def get_sales_date(request, date):
    token = request.headers.get('Authorization')
    if not token:
        return JsonResponse({"error": "Unauthorized"}, status=401)
    try:
        query_date = datetime.strptime(
            date, "%Y-%m-%d"
        ).date()
    except ValueError:
        return JsonResponse(
            {"error": "Invalid date format. Gunakan format YYYY-MM-DD."}, status=400
        )
    connection = connect_to_postgres()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT user_id FROM AuthOfficeToken WHERE token = %s AND expires_at > NOW()",
                (token,),
            )
            result = cursor.fetchone()
            if not result:
                return JsonResponse({"error": "Unauthorized"}, status=401)
            user_id = result[0]
            cursor.execute(
                """
                SELECT id, sale_date, total_price FROM Sales
                WHERE DATE(sale_date) = %s
                """,
                (query_date,),
            )
            sales_data = cursor.fetchall()
            sales = [
                {"id": row[0], "sale_date": row[1], "total_price": row[2]}
                for row in sales_data
            ]
            return render(
                request, "protected.html", {"date": query_date, "sales": sales}
            )
    except Exception as e:
        return JsonResponse({"error": "Server error"}, status=500)
    finally:
        connection.close()


def get_sales_detail(request, id):
    token = request.headers.get("Authorization")
    if not token:
        return JsonResponse({"error": "Unauthorized"}, status=401)
    connection = connect_to_postgres()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT user_id FROM AuthOfficeToken WHERE token = %s AND expires_at > NOW()",
                (token,),
            )
            result = cursor.fetchone()
            if not result:
                return JsonResponse({"error": "Unauthorized"}, status=401)
            user_id = result[0]
            cursor.execute(
                "SELECT id, sale_date, total_price FROM Sales WHERE id = %s", (id,)
            )
            sales_data = cursor.fetchone()
            if not sales_data:
                return JsonResponse({"error": "Penjualan tidak ditemukan"}, status=404)
            sales = {
                "id": sales_data[0],
                "sale_date": sales_data[1],
                "total_price": sales_data[2],
            }
            cursor.execute(
                "SELECT id, product_name, quantity, price, total_price FROM SalesProduct WHERE sales_id = %s",
                (id,),
            )
            products_data = cursor.fetchall()
            products = [
                {
                    "id": row[0],
                    "product_name": row[1],
                    "quantity": row[2],
                    "price": row[3],
                    "total_price": row[4],
                }
                for row in products_data
            ]
            return render(
                request, "detail.html", {"sales": sales, "products": products}
            )
    except Exception as e:
        return JsonResponse({"error": "Server error"}, status=500)
    finally:
        connection.close()


@csrf_exempt
def logout(request):
    if request.method == "POST":
        token = request.headers.get("Authorization")
        if not token:
            return JsonResponse({"error": "AuthToken not exist"}, status=400)
        connection = connect_to_postgres()
        try:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM AuthOfficeToken WHERE token = %s", (token,))
                connection.commit()
                return JsonResponse({"message": "Berhasil Log Out"}, status=200)
        except Exception as e:
            return JsonResponse({"error": "Server error"}, status=500)
        finally:
            connection.close()
    return JsonResponse({"error": "Invalid request method"}, status=405)
