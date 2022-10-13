import pandas as pd
from sqlalchemy import  create_engine
from pdynamics import crm
from io import StringIO  
crmurl = "https://antdev.crm5.dynamics.com/"
user = "antd01@antsolution.vn"
password = "DataTeam@123456"
clientid = "1270c272-1ab3-4b86-9a34-8681e36dba68"
clientsecret = "1o-o~.RDc81x1M.3R-W8TqoN7Kd2mA3_D."
crmorg = crm.client(crmurl, user, password, clientid, client_secret=clientsecret)
crmorg.test_connection()
QUERY_FULL = "accounts?$select=accountid,ant_dateofbirth,createdon,modifiedon,telephone1"
data = crmorg.get_data(query=QUERY_FULL)
data = data["value"]
df = pd.DataFrame(data)
df = df.fillna("")
def change_date(data):
    data = data.split("T")[0]
    data = data.split('/')
    data = "".join(data)
#     data = data.split('-')
#     data = "".join(data)
    return data

def change_birth(data):
    data = data.split("T")[0]
    data = data.split('/')
    data = "".join(data)
    data = data.split('-')
    data = "".join(data)
    return data

birthday = df['ant_dateofbirth'].apply(change_birth)
customer_code = df['accountid']
integration_id = "1" + "~" +df['accountid']
datasoure_id = 1
active_flg = True
delete_flg = False
createon = df['createdon'].apply(change_date)
modifiedon = df['modifiedon'].apply(change_date)
x_custom = False
phone = df["telephone1"]
df1 = pd.DataFrame(list(integration_id.values),list(customer_code.values))
output = StringIO()


engine = create_engine('postgresql://postgres:postgres@localhost:5432/Demo')
# df.to_sql("accountCRM", engine, if_exists="append")
connection = engine.raw_connection()
cursor = connection.cursor()

command = '''DROP TABLE IF EXISTS localytics_app2;
CREATE TABLE localytics_app2
(
A char(100),
B char(100)
);'''
cursor.execute(command)
connection.commit()

connection = engine.raw_connection()
df1.to_csv(output, sep='\t', header=False, index=False)
output.seek(0)
contents = output.getvalue()
cur = connection.cursor()
cur.copy_from(output, 'localytics_app2', null="")    
connection.commit()
cur.close()
