from fastapi.encoders import jsonable_encoder

from cProfile import label
from genericpath import exists
import shutil
import time
from datetime import datetime, timedelta
from fileinput import filename
from typing import Any, Union,Optional
from unicodedata import name
from sqlalchemy.sql import text
from gcloud import storage
from oauth2client.service_account import ServiceAccountCredentials
import os
import sqlalchemy
import jwt
import pandas as pd
import psycopg2
import uvicorn
from dotenv import load_dotenv
import json
from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from fastapi.security import HTTPBearer
from pdynamics import crm
from pydantic import ValidationError
from sqlalchemy import  create_engine
import os

load_dotenv()

SECURITY_ALGORITHM = os.getenv("SECURITY_ALGORITHM")
SECRET_KEY = os.getenv("SECRET_KEY")
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DATABASE = os.getenv("DB_DATABASE")
PATH = os.getenv("DICTIONARY")

connection_string = "host={} dbname={} user={} password={}".format(DB_HOST,DB_DATABASE,DB_USER,DB_PASSWORD)
connection_string_alchemy = "postgresql://{}:{}@{}:5432/{}".format(DB_USER,DB_PASSWORD,DB_HOST,DB_DATABASE)

f = open(PATH)
credentials_dict = json.load(f)

app = FastAPI()

list_role = ["root","admin",'editor','sysadmin','viewer']

reusable_oauth2 = HTTPBearer(scheme_name="Authorization")

def generate_token(token_id: Union[str, Any] = "fake", user_id: Union[str, Any] = "fake") -> str:
    expire = datetime.utcnow() + timedelta(seconds=60 * 60 * 24 * 3)  # Expired after 3 days
    to_encode = {"exp": expire, "token_id": token_id, "user_id": user_id}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=SECURITY_ALGORITHM)
    return encoded_jwt

def validate_token(http_authorization_credentials=Depends(reusable_oauth2)) -> str:
    """
    Decode JWT token to get token_id => return token_id
    """
    try:
        payload = jwt.decode(http_authorization_credentials.credentials, SECRET_KEY, algorithms=[SECURITY_ALGORITHM])
        if payload.get("exp") < time.time():
            raise HTTPException(status_code=403, detail="Token expired")
        return payload.get("user_id")
    except (jwt.PyJWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials",
        )

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/datasetCRM/{QUERY}", tags=["Dataset_CRM"], status_code=200, dependencies=[Depends(validate_token)])
async def read_datasetCRM(QUERY: str, response: Response):
    try:
        crmurl = "https://antdev.crm5.dynamics.com/"
        user = "lam.tp@antsolution.vn"
        password = "Socnamini@2022"
        clientid = "1270c272-1ab3-4b86-9a34-8681e36dba68"
        clientsecret = "1o-o~.RDc81x1M.3R-W8TqoN7Kd2mA3_D."
        crmorg = crm.client(crmurl, user, password, clientid, client_secret=clientsecret)
        crmorg.test_connection()
        QUERY_FULL = "accounts?$select=" +QUERY
        data = crmorg.get_data(query=QUERY_FULL)
        data = data["value"]
        response.status_code = status.HTTP_200_OK
        return {"status": "success", "message": "dataset retrieving pass", "data": {"dataset": data}}
    except:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"status": "failed", "message": "dataset retrieving failed", "data": {}}

@app.get("/accountCRM", tags=["Dataset_CRM"], status_code=200)
async def add_account(response: Response):
    try:
        crmurl = "https://antdev.crm5.dynamics.com/"
        user = "lam.tp@antsolution.vn"
        password = "Socnamini@2022"
        clientid = "1270c272-1ab3-4b86-9a34-8681e36dba68"
        clientsecret = "1o-o~.RDc81x1M.3R-W8TqoN7Kd2mA3_D."
        crmorg = crm.client(crmurl, user, password, clientid, client_secret=clientsecret)
        crmorg.test_connection()
        QUERY_FULL = "accounts?$select=accountid,accountnumber,ant_dateofbirth,name,telephone1"
        data = crmorg.get_data(query=QUERY_FULL)
        data = data["value"]
        df = pd.DataFrame(data)
        df = df.fillna("")
        engine = create_engine('postgresql://postgres:postgres@localhost:5432/DatabaseCRM')
        df.to_sql("accountCRM", engine, if_exists="append")
        response.status_code = status.HTTP_200_OK
        # return {"status": "success", "message": "dataset retrieving pass","data":{"dataset": data}}
        return df
    except:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"status": "failed", "message": "dataset retrieving failed", "data": {}}

# @app.post("/accountCRM/{QUERY}", tags=["Dataset_CRM"], status_code=200, dependencies=[Depends(validate_token)])
# async def add_account(QUERY: str, response: Response):
#     try:
#         if QUERY.lower() == "account":
#             crmurl = "https://antdev.crm5.dynamics.com/"
#             user = "lam.tp@antsolution.vn"
#             password = "Socnamini@2020"
#             clientid = "1270c272-1ab3-4b86-9a34-8681e36dba68"
#             clientsecret = "1o-o~.RDc81x1M.3R-W8TqoN7Kd2mA3_D."
#             crmorg = crm.client(crmurl, user, password, clientid, client_secret=clientsecret)
#             crmorg.test_connection()
#             QUERY_FULL = "accounts?$select=accountid,accountnumber,ant_dateofbirth,name,telephone1"
#             data = crmorg.get_data(query=QUERY_FULL)
#             data = data["value"]
#             df = pd.DataFrame(data)
#             df = df.fillna("")
#             # engine = create_engine(
#             #     "postgresql://postgres:1qaZ2wsX@34.143.151.242:5432/EG_database"
#             # )
#             # df.to_sql("accountCRM", engine, if_exists="append", index=False)

#             response.status_code = status.HTTP_200_OK
#             return {"status": "success", "message": "dataset retrieving pass","data":df}
#     except:
#         response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
#         return {"status": "failed", "message": "dataset retrieving failed"}

# @app.post("/accountCRM/{QUERY}", tags=["Dataset_CRM"])
# async def add_account():
#     try:
#             crmurl = "https://antdev.crm5.dynamics.com/"
#             user = "lam.tp@antsolution.vn"
#             password = "Socnamini@2020"
#             clientid = "1270c272-1ab3-4b86-9a34-8681e36dba68"
#             clientsecret = "1o-o~.RDc81x1M.3R-W8TqoN7Kd2mA3_D."
#             crmorg = crm.client(crmurl, user, password, clientid, client_secret=clientsecret)
#             crmorg.test_connection()
#             QUERY_FULL = "accounts?$select=accountid,accountnumber,ant_dateofbirth,name,telephone1"
#             data = crmorg.get_data(query=QUERY_FULL)
#             data = data["value"]
#             df = pd.DataFrame(data)
#             df = df.fillna("")
#             engine = create_engine(
#                  "postgresql://{}:{}@34.87.131.121/{}".format(db_user,db_password,db_name)
#             )
#             df.to_sql("accountCRM", engine, if_exists="append", index=False)
#             return {"status": "success", "message": "dataset retrieving pass"}
#     except:
#         return {"status": "failed", "message": "dataset retrieving failed"}

@app.post("/add-userlogin/",tags=["Account"],dependencies=[Depends(validate_token)])
def add_user(first_name: str, last_name: str, age: int, username: str, password: str,groupID: int, role: str = Query("viewer",enum=list_role),token_name: str = Depends(validate_token)):
    permiss = ["root","admin","sysadmin"]
    rolee = str(role)
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
        """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if role_currentuser in permiss and list_role.index(role_currentuser) < list_role.index(rolee):
            try:
                if len(password) > 8:
                    exists_account_query = """
                        select exists (
                            select 1
                            from account
                            where username = %s
                        )"""
                    cur.execute(exists_account_query,(str(username),))
                    if not cur.fetchone()[0]:
                        exists_query = f"""
                            INSERT INTO public.account(
                            firstname, lastname, age, username, password,groupID,role)
                            VALUES (%s, %s, %s, %s, %s, %s, N'{rolee}');
                            """
                        cur.execute(exists_query, (first_name, last_name, age, username, password, groupID))
                        return f"Account {username} is added with role {rolee} "
                    else:
                        return f"Username {username} already exist"
                else:
                    return "Length password too short"
            except:
                return f"Group {groupID} is not exist"
        else:
            return f"Your user isn't allowed to add user with role {role}"
    except:
        return "Error"

@app.put("/update-user/",tags=['Account'],status_code=200, dependencies=[Depends(validate_token)])
def update_user(user_updated:str, firstname: Optional[str] = None, lastname: Optional[str] = None , age:  Optional[int] = None, password:  Optional[str] = None,groupid: Optional[int] = None, token_name: str = Depends(validate_token)):
    permiss = ["root","admin","sysadmin"]
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if role_currentuser in permiss and user_updated != 'antsolution' :
            exists_account_query = """
                select exists (
                    select 1
                    from account
                    where username = %s
                )"""
            cur.execute(exists_account_query,(str(user_updated),))
            if cur.fetchone()[0]: 
                if password:
                    if len(password)>8:
                        list_updated = {
                            "firstname":firstname,
                            "lastname":lastname,
                            "age": age,
                            "password": password,
                            "groupid": groupid
                            }
                        for parameter in list_updated:
                            if list_updated[parameter]:
                                exists_query = """UPDATE public.account SET {} = %s WHERE username=%s;""".format(parameter)
                                cur.execute(exists_query,(list_updated[parameter],user_updated,))      
                        return f"User {user_updated} is updated"
                    else:
                        return "Length password too short"
                else:
                    list_updated = {
                            "firstname":firstname,
                            "lastname":lastname,
                            "age": age,
                            "groupid": groupid
                            }
                    for parameter in list_updated:
                        if list_updated[parameter]:
                            exists_query = """UPDATE public.account SET {} = %s WHERE username=%s;""".format(parameter)
                            cur.execute(exists_query,(list_updated[parameter],user_updated,))      
                    return f"User {user_updated} is updated"
            else:
                return "username is not exist"        
        else: 
            return "Your user isn't allowed to update user"
    except:
        return "GroupId is not exist"

@app.put("/Update-role/" ,tags=["Account"],status_code=200, dependencies=[Depends(validate_token)])
def add_user(username: str, new_role: str = Query("viewer",enum=list_role),token_name: str = Depends(validate_token)):
    permiss = ["root","admin","sysadmin"]
    try:
        conn = psycopg2.connect(
        connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        try:
            role_query = """
                SELECT role FROM public.account
                WHERE username = %s ;
                """
            cur.execute(role_query,(str(username),))
            role_updated_user = cur.fetchone()[0].strip()
        except:
            return f"User {username} is not exist"
        if role_currentuser in permiss and list_role.index(role_currentuser) < list_role.index(role_updated_user) and list_role.index(role_currentuser) < list_role.index(new_role):
            exists_query = """UPDATE public.account
                            SET  role=%s
                            WHERE username=%s;"""
            cur.execute(exists_query,(str(new_role),str(username))) 
            return f"User {username} is updated with role {new_role}"
        else:
            return f"Your user isn't allowed to update role {new_role} for user {username} "
    except:
        return "Error"

@app.delete("/delete-userlogin/" ,tags=["Account"],status_code=200, dependencies=[Depends(validate_token)])
def delete_user(user:str,token_name: str = Depends(validate_token)):
    permiss = ["root","admin","sysadmin"]
    try:
        conn = psycopg2.connect(
        connection_string
    )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        try:
            role_query = """
                SELECT role FROM public.account
                WHERE username = %s ;
                """
            cur.execute(role_query,(str(user),))
            role_deleted_user = cur.fetchone()[0].strip()
        except:
            return f"User {user} is not exist"
        
        if role_currentuser in permiss and str(user).strip() != token_name and list_role.index(role_currentuser) < list_role.index(role_deleted_user):
            exists_query = """
                DELETE FROM account
                WHERE username = %s ;
                """
            cur.execute(exists_query,(str(user),))
            return f"User {user} is deleted"
        else:
            return "Your user isn't allowed to delete {}".format(str(user))
    except:
        return {"status": "failed", "message": "dataset retrieving failed"}

@app.get("/login/",tags=["Account"])
async def check_login(user: str, pas: str):
    conn = psycopg2.connect(
        connection_string
    )
    conn.set_session(autocommit=True)
    cur = conn.cursor()
    exists_query = """
        select exists (
            select 1
            from account
            where username = %s and password = %s
        )"""
    cur.execute(exists_query, (user, pas))
    if cur.fetchone()[0]:
        tokenize = generate_token(user_id=user)
        created_dt = datetime.utcnow()
        expire = datetime.utcnow() + timedelta(seconds=60 * 60 * 24 * 3)  # Expired after 3 days
        role_query = """SELECT role from public.account
        where username = %s ;"""
        cur.execute(role_query, (str(user),))
        role = cur.fetchone()[0].strip()
        # exists_query = f"""
        # INSERT INTO public.token_management(
        #         username,token,role,created_date,expire_date)
        #         VALUES (%s, %s, %s,'{created_dt}','{expire}');
        #         """
        # cur.execute(exists_query, (user, str(tokenize),role))
        return {"Token": tokenize}
    return "The username or password is incorrect"

@app.post("/add-group/",tags=["Group"],dependencies=[Depends(validate_token)])
def add_group(groupID: int, groupname: str ,token_name: str = Depends(validate_token)):
    permiss = ["root","admin","sysadmin"]
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if role_currentuser in permiss:
            try:
                exists_query = """
                    INSERT INTO public.groupp(
                    groupid,groupname)
                    VALUES (%s,%s)
                    """
                cur.execute(exists_query,(groupID,groupname))
                return "Group {} is updated".format(groupname)
            except:
                return "{} already exist".format(groupID)
        else:
            return "Your user isn't allowed to add group"
    except:
        return "Error"

@app.put("/update-group/",tags=["Group"],dependencies=[Depends(validate_token)])
def add_group(groupID: int, new_groupname: str ,token_name: str = Depends(validate_token)):
    permiss = ["root","admin","sysadmin"]
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if role_currentuser in permiss:
            exists_group_query = f"""
                select exists (
                    select 1
                    from groupp
                    where groupid = {groupID}
                )"""
            cur.execute(exists_group_query)
            if cur.fetchone()[0]:
                exists_query = f"""UPDATE public.groupp SET groupname = N'{new_groupname}' WHERE groupid={groupID};"""
                cur.execute(exists_query) 
                return "Group {} is updated".format(new_groupname)
            else:
                return "Group {} is not exist".format(groupID)    
        else:
            return "Your user isn't allowed to update group"
    except:
        return "error"

@app.delete("/delete-group/",tags=["Group"],dependencies=[Depends(validate_token)])
def delete_group(groupID: int,token_name: str = Depends(validate_token)):
    permiss = ["root","admin","sysadmin"]
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if role_currentuser in permiss:
            exists_group_query = f"""
                select exists (
                    select 1
                    from groupp
                    where groupid = {groupID}
                )"""
            cur.execute(exists_group_query)
            if cur.fetchone()[0]:
                try:
                    exists_query = f"""
                    DELETE FROM public.groupp
                    WHERE groupid={groupID};
                    """
                    cur.execute(exists_query)
                    return f"Group {groupID} is deleted"
                except:
                    exists_query = f"""SELECT username
                                     FROM public.account
                                    where groupid = {groupID};"""
                    cur.execute(exists_query)
                    list_user = []
                    for user in cur.fetchall():
                        list_user.append(user[0].strip())
                    return "You need to delete all of user "+str({i for i in list_user})
            else:
                return "Group {} is not exist".format(groupID)
        else:
            return "Your user isn't allowed to delete group"
    except:
        return "error"

@app.post("/add-report/",tags=["Report"],dependencies=[Depends(validate_token)])
def add_report(reportID: int, reportname: str,groupid:Optional[str] = None,token_name: str = Depends(validate_token)):
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if groupid:
            exists_group_query = f"""
                select exists (
                    select 1
                    from groupp
                    where groupid = {groupid}
                )"""
            cur.execute(exists_group_query)
            if cur.fetchone()[0]:
                if role_currentuser in ["root","admin","editor"]:
                    try:
                        exists_query = """
                        INSERT INTO public.report(
                        reportid,reportname,groupid)
                        VALUES (%s,%s,%s)
                        """
                        cur.execute(exists_query,(reportID,reportname,groupid))
                        return "Report {} is added".format(reportID)
                    except:
                        return f"Report {reportID} is already exist"
                else:
                    return "Your user is not allow to add report for group"
            else:
                return f"Group {groupid} is not exist"
        else:
            if role_currentuser in ["root","admin","editor","sysadmin"]:
                try:
                    exists_query = """
                        INSERT INTO public.report(
                        reportid,reportname)
                        VALUES (%s,%s)
                        """
                    cur.execute(exists_query,(reportID,reportname,))
                    return "Report {} is added".format(reportID)
                except:
                    return f"Report {reportID} is already exist"
            else:
                return "Your user is not allow to add report"
    except:
        return "Error"

@app.put("/update-report/",tags=["Report"],dependencies=[Depends(validate_token)])
def update_report(reportID: int, new_reportname:  Optional[str] = None, new_groupID: Optional[int] = None ,token_name: str = Depends(validate_token)):
    permiss = ["root","admin","editor"]
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if role_currentuser in permiss:
            exists_report_query = f"""
                select exists (
                    select 1
                    from report
                    where reportid = {reportID}
                )"""
            cur.execute(exists_report_query)
            if cur.fetchone()[0]:
                if new_groupID:
                    exists_group_query = f"""
                    select exists (
                        select 1
                        from groupp
                        where groupid = {new_groupID}
                    )"""
                    cur.execute(exists_group_query)
                    if cur.fetchone()[0]:
                        list_updated = {
                        "reportname": new_reportname,
                        "groupid" : new_groupID
                        }
                        for parameter in list_updated:
                            if list_updated[parameter]:
                                exists_query = """UPDATE public.report SET {} = %s WHERE reportid=%s;""".format(parameter)
                                cur.execute(exists_query,(list_updated[parameter],reportID,))
                        return "Report {} is updated".format(reportID)
                    else:
                        return f"Group {new_groupID} is not exist"
                else:
                    exists_query = """UPDATE public.report SET reportname = %s WHERE reportid=%s;"""
                    cur.execute(exists_query,(new_reportname,reportID,)) 
                    return "Report {} is updated".format(reportID)
            else:
                return "Report {} is not exist".format(reportID)    
        else:
            return "Your user isn't allowed to update report"
    except:
        return "error"

@app.delete("/delete-report/",tags=["Report"],dependencies=[Depends(validate_token)])
def delete_report(reportID: int,token_name: str = Depends(validate_token)):
    permiss = ["root","admin","editor"]
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        role_query = """
            SELECT role FROM public.account
            WHERE username = %s ;
            """
        cur.execute(role_query,(str(token_name),))
        role_currentuser = cur.fetchone()[0].strip()
        if role_currentuser in permiss:
            exists_report_query = f"""
                select exists (
                    select 1
                    from report
                    where reportid = {reportID}
                )"""
            cur.execute(exists_report_query)
            if cur.fetchone()[0]:
                exists_query = f"""
                DELETE FROM public.report
                WHERE reportid={reportID};
                """
                cur.execute(exists_query)
                return f"Report {reportID} is deleted"
            else:
                return "Report {} is not exist".format(reportID)
        else:
            return "Your user isn't allowed to delete report {}".format(reportID)
    except:
        return "error"

@app.put("/update-my-profile/",tags=['My-Profile'],status_code=200, dependencies=[Depends(validate_token)])
def update_user( firstname: Optional[str] = None, lastname: Optional[str] = None , age:  Optional[int] = None, password:  Optional[str] = None, token_name: str = Depends(validate_token)):
    try:
        conn = psycopg2.connect(
            connection_string
        )
        conn.set_session(autocommit=True)
        cur = conn.cursor()
        if password:
            if len(password)>8:
                list_updated = {
                    "firstname":firstname,
                    "lastname":lastname,
                    "age": age,
                    "password": password,
                    }
                for parameter in list_updated:
                    if list_updated[parameter]:
                        exists_query = """UPDATE public.account SET {} = %s WHERE username=%s;""".format(parameter)
                        cur.execute(exists_query,(list_updated[parameter],str(token_name),))      
                return f"User {token_name} is updated"
            else:
                return "Length password too short"
        else:
            list_updated = {
                    "firstname":firstname,
                    "lastname":lastname,
                    "age": age           
                    }
            for parameter in list_updated:
                if list_updated[parameter]:
                    exists_query = """UPDATE public.account SET {} = %s WHERE username=%s;""".format(parameter)
                    cur.execute(exists_query,(list_updated[parameter],str(token_name),))      
            return f"User {token_name} is updated"     
    except:
        return "Error"

@app.get("/view-my-profile/",tags=['My-Profile'],status_code=200, dependencies=[Depends(validate_token)])
def my_profile(token_name: str = Depends(validate_token)):
    conn = psycopg2.connect(
            connection_string
        )
    conn.set_session(autocommit=True)
    cur = conn.cursor()
    exists_query = """SELECT firstname, lastname, age, username, password, groupid, role
	FROM public.account
	WHERE username = %s;"""
    cur.execute(exists_query,(str(token_name),))
    result = cur.fetchone()
    return {"first name": result[0].strip(), 
        "last name": result[1].strip(),
        "age" : result[2],
        "Username": result[3].strip(),
        "password":result[4].strip(),
        "groupid":result[5],
        "role":result[6].strip()
        }


@app.post("/upload-file/")
async def create_upload_file_excel(uploaded_file: UploadFile = File(...)):
    file_location = f"app/{uploaded_file.filename}"
    #file_location = f"{uploaded_file.filename}"
    with open(file_location, "wb+") as file_object:
        shutil.copyfileobj(uploaded_file.file, file_object)
    return {"info": f"file '{uploaded_file.filename}' saved at '{file_location}'"}

@app.get("/transform", status_code=200, dependencies=[Depends(validate_token)])
async def transform_excel_file(file_name: str):
    try:
        file_location = f"app/{file_name}"
        df = pd.read_excel(file_location)
        # df = pd.read_excel(file_location)
        df = df.fillna("")
        engine = create_engine(
                connection_string_alchemy
            )
        # table_name = file_name.split(".")
        # table_name = table_name[0]
        df.to_sql(file_name.split(".")[0], engine, if_exists="append")
        # return {"status": "success", "message": "dataset retrieving pass", "data": {"dataset": df["Married Status"]}}
        return {"status": "success", "message": "dataset retrieving pass"}
    except:
        return {"status": "failed", "message": "dataset retrieving failed", "data": file_name.split(".")[0]}

@app.get("/upload_to_ggcloud_storage", status_code=200, dependencies=[Depends(validate_token)])
async def upload_togcp(filename:str):
    file_location = f"app/{filename}"
    try:
        credentials = ServiceAccountCredentials.from_json_keyfile_dict(
            credentials_dict
        )
        client = storage.Client(credentials=credentials, project='Ant Data Platform')
        bucket = client.get_bucket('egdatastore')
        blob = bucket.blob(file_location)
        blob.upload_from_filename(file_location)
        return {"status": "success", "message": "dataset retrieving pass"}
    except:
        return {"status": "failed", "message": "dataset retrieving failed"} 

@app.get("/export_to_csv", status_code=200, dependencies=[Depends(validate_token)])
async def export_csv(table_name: str):
    try:
        engine = sqlalchemy.create_engine(connection_string_alchemy)
        sql = '''
            SELECT * FROM public."{}";
            '''.format(table_name)
        with engine.connect().execution_options(autocommit=True) as conn:
            query = conn.execute(text(sql))         
        df = pd.DataFrame(query.fetchall())
        if '_airbyte_raw_' in table_name:
            data = pd.DataFrame(dict(df.iloc[0,1]),index = [0])
            for i in range(1,len(df)):
                data = data.append(dict(df.iloc[i,1]), ignore_index=True)
            data.to_csv(table_name+'.csv')
            # file_location = f"app/{filename}"
            file_location = f"{table_name}.csv"
            credentials = ServiceAccountCredentials.from_json_keyfile_dict(
                credentials_dict
                        )
            client = storage.Client(credentials=credentials, project='Ant Data Platform')
            bucket = client.get_bucket('egdatastore')
            blob = bucket.blob("dashboard/"+file_location)
            blob.upload_from_filename(file_location)
        else:
            df.to_csv(table_name+'.csv')
        return {"status": "success", "message": "dataset retrieving pass"}
    except:
        return {"status": "failed", "message": "dataset retrieving failed"}    


@app.get("/test",status_code=200)
async def test_get(response: Response):
    dict1 ={
    "emp1": {
        "name": "Lisa",
        "designation": "programmer",
        "age": "34",
        "salary": "54000"
    }
    }
    response.status_code = status.HTTP_200_OK
    return dict1