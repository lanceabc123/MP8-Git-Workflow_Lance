from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from passlib.context import CryptContext
from db import DBManager
import models as model

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# --- Security Configuration ---
SECRET_KEY = "SUPER_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

db = DBManager(host="localhost", user="root", password="", database="logistics_db")

# ==========================================
# --- JWT HELPER FUNCTIONS ---
# ==========================================
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Not authenticated")

def get_current_user_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        if token.startswith("Bearer "):
            token = token[7:]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


# ==========================================
# --- MP4: RAW JSON API ROUTES (POSTMAN) ---
# ==========================================
@app.post("/register", status_code=201, tags=["Auth"])
def register_user(user: model.UserCreate):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (user.email,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")
            hashed_pwd = get_password_hash(user.password).encode("utf-8")
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (user.name, user.email, hashed_pwd))
            connection.commit()
            return {"message": "User registered successfully"}
    finally:
        connection.close()

@app.post("/login", response_model=model.Token, tags=["Auth"])
def login(user: model.UserAuth):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (user.email,))
            db_user = cursor.fetchone()
            if not db_user:
                raise HTTPException(status_code=400, detail="Incorrect email or password")
            hashed_pwd = db_user["password"]
            if isinstance(hashed_pwd, bytes):
                hashed_pwd = hashed_pwd.decode("utf-8")
            if not verify_password(user.password, hashed_pwd):
                raise HTTPException(status_code=400, detail="Incorrect email or password")
            access_token = create_access_token(data={"sub": db_user["email"]})
            return {"access_token": access_token, "token_type": "bearer"}
    finally:
        connection.close()

@app.get("/getItem")
def get_all_items(current_user: str = Depends(verify_jwt_token)):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM inventory_items")
            return cursor.fetchall()
    finally:
        connection.close()

@app.post("/addItem", status_code=201, tags=["Auth"])
def create_item(item: model.ItemCreate, current_user: str = Depends(verify_jwt_token)):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = "INSERT INTO inventory_items (item_name, quantity, price, is_fragile, date_added) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(query, (item.name, item.quantity, item.price, item.is_fragile, item.date_added))
            connection.commit()
            return {"message": f"Item created successfully, ID: {cursor.lastrowid}"}
    except Exception as err_msg:
        return {"message": f"Error: {err_msg}"}
    finally:
        connection.close()

@app.get("/getItem/{item_id}", tags=["Auth"])
def get_item(item_id: int, current_user: str = Depends(verify_jwt_token)):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = "SELECT * FROM inventory_items WHERE item_id = %s"
            cursor.execute(query, (item_id,))
            return cursor.fetchall()
    finally:
        connection.close()

@app.put("/updateStock/{item_id}", tags=["Auth"])
def update_stock(item_id: int, item: model.StockUpdate, current_user: str = Depends(verify_jwt_token)):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = "UPDATE inventory_items SET quantity = %s WHERE item_id = %s"
            cursor.execute(query, (item.new_qty, item_id))
            connection.commit()
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Item not found")
            return {"message": "OK"}
    finally:
        connection.close()

@app.delete("/deleteItem/{item_id}", tags=["Auth"])
def delete_item(item_id: int, current_user: str = Depends(verify_jwt_token)):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            query = "DELETE FROM inventory_items WHERE item_id = %s"
            cursor.execute(query, (item_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Item not found")
            connection.commit()
            return {"message": "Item deleted successfully"}
    finally:
        connection.close()

# ==========================================
# --- MP5/MP6: GUI WEB ROUTES (BROWSER) ---
# ==========================================
@app.get("/gui/login")
def render_login(request: Request, msg: str = None):
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg})

@app.post("/gui/login")
def handle_login(request: Request, email: str = Form(...), password: str = Form(...)):
    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            db_user = cursor.fetchone()
            if not db_user:
                return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
            
            hashed_pwd = db_user["password"]
            if isinstance(hashed_pwd, bytes):
                hashed_pwd = hashed_pwd.decode("utf-8")
                
            if not verify_password(password, hashed_pwd):
                return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})

            access_token = create_access_token(data={"sub": db_user["email"]})
            response = RedirectResponse(url="/gui/dashboard?msg=Login+Successful", status_code=303)
            response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
            return response
    finally:
        connection.close()

@app.get("/gui/register")
def render_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/gui/register")
def handle_register(
    request: Request, 
    name: str = Form(...), 
    email: str = Form(...), 
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    # Verify passwords match before hitting the database
    if password != confirm_password:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Passwords do not match."})

    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return templates.TemplateResponse("register.html", {"request": request, "error": "Email is already registered"})
            
            hashed_pwd = get_password_hash(password).encode("utf-8")
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_pwd))
            connection.commit()
            return RedirectResponse(url="/gui/login?msg=Registration+Successful.+Please+log+in.", status_code=303)
    finally:
        connection.close()

@app.get("/gui/logout")
def logout():
    response = RedirectResponse(url="/gui/login?msg=You+have+been+logged+out.", status_code=303)
    response.delete_cookie("access_token")
    return response

@app.get("/gui/dashboard")
def render_dashboard(request: Request, msg: str = None):
    user = get_current_user_from_cookie(request)
    if not user:
        return RedirectResponse(url="/gui/login", status_code=303)

    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM inventory_items")
            items = cursor.fetchall()
            return templates.TemplateResponse("dashboard.html", {"request": request, "items": items, "user": user, "msg": msg})
    finally:
        connection.close()

@app.post("/gui/addItem")
def gui_add_item(request: Request, name: str = Form(...), quantity: int = Form(...), price: float = Form(...), date_added: str = Form(...)):
    if not get_current_user_from_cookie(request):
        return RedirectResponse(url="/gui/login", status_code=303)

    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO inventory_items (item_name, quantity, price, is_fragile, date_added) VALUES (%s, %s, %s, %s, %s)", 
                           (name, quantity, price, 0, date_added))
            connection.commit()
    finally:
        connection.close()
    return RedirectResponse(url="/gui/dashboard?msg=Item+Added+Successfully", status_code=303)

## Dito ka nagka problem from mp6 to mp7
## Test comment number two
## Test comment number three

@app.get("/gui/deleteItem/{item_id}")
def gui_delete_item(request: Request, item_id: int):
    if not get_current_user_from_cookie(request):
        return RedirectResponse(url="/gui/login", status_code=303)

    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM inventory_items WHERE item_id = %s", (item_id,))
            connection.commit()
    finally:
        connection.close()
    return RedirectResponse(url="/gui/dashboard?msg=Item+Deleted+Successfully", status_code=303)

@app.get("/gui/updateItem/{item_id}")
def render_update_item(request: Request, item_id: int):
    if not get_current_user_from_cookie(request):
        return RedirectResponse(url="/gui/login", status_code=303)

    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM inventory_items WHERE item_id = %s", (item_id,))
            item = cursor.fetchone()
            return templates.TemplateResponse("update.html", {"request": request, "item": item})
    finally:
        connection.close()
        active_node = "Initial Setup"
@app.post("/gui/updateItem/{item_id}")
def handle_update_item(request: Request, item_id: int, quantity: int = Form(...), price: float = Form(...)):
    if not get_current_user_from_cookie(request):
        return RedirectResponse(url="/gui/login", status_code=303)

    connection = db.get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE inventory_items SET quantity = %s, price = %s WHERE item_id = %s", (quantity, price, item_id))
            connection.commit()
    finally:
        connection.close()
    return RedirectResponse(url="/gui/dashboard?msg=Stock+Updated+Successfully", status_code=303)

  