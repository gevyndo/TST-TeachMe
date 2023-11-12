
from typing import Annotated
from fastapi import Depends
from fastapi import FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import json
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

class User:
	def __init__(self, name, password, id, role):
		self.name = name
		self.password = password
		self.id = id
		self.role=role
		
class Student:
	def __init__(self, name, studentId):
		self.name = name
		self.studentId = studentId

		
class Teacher:
	def __init__(self, name, teacherID, spesialisasi):
		self.name = name
		self.teacherID = teacherID
		self.spesialisasi = spesialisasi
		
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

app = FastAPI()
json_file='student.json'
json_file2='teacher.json'
json_file3='appointment.json'
json_file4='akun.json'

oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")
with open(json_file,'r') as read:
	data_student=json.load(read)

with open(json_file2,'r') as read:
	data_teacher=json.load(read)

with open(json_file3,'r') as read:
	data_appointment=json.load(read)
with open(json_file4,'r') as read:
	data_akun=json.load(read)

def authenticate_user(username:str,password:str):
	user_correct=False
	for data in data_akun["akun"]:
		if username == data["name"] and password == data["password"]:
			user_correct = True
			user = User(name=data["name"],password=data["password"],id=data["akunID"],role=data["role"])
			return user
	if not user_correct:
		raise HTTPException(status_code=401, detail="Invalid Username or Password")
		
async def get_curr_user(token : str = Depends(oauth_scheme)):
	payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
	if payload.get('role') == 'teacher':
		try:
			for data in data_teacher["teacher"]:
				if payload.get('id') == data['id']:
					user = Teacher(name = payload.get('name'), teacherID=payload.get('id'), spesialisasi = data["spesialisasi"] )
					return user
		except:
			raise HTTPException(status_code=401, detail="Invalid Username or Password")
	elif payload.get('role') == "student":
		try:
			for data in data_student["student"]:
				if payload.get("id") == data["id"]:
					user = Student(name = payload.get("name"), studentId=payload.get("id"))
					return user
		except:
			raise HTTPException(status_code=401, detail="Invalid Username r Password")
        
	
	
	

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
	user = authenticate_user(form_data.username,form_data.password)
	token = jwt.encode({'username':user.name, 'id' : user.id, 'role':user.role}, SECRET_KEY)
	return {"access_token": token, "token_type":"bearer"}

@app.get('/all/teacher')
async def get_all_teacher(user: Student = Depends(get_curr_user)):
	if isinstance(user, Student):
		return data_teacher["teacher"]
	else:
		raise HTTPException(status_code=405, detail="unauthorized")

def write_data_student(data):
	with open(json_file, "w") as write_file:
		json.dump(data,write_file)
def write_data_akun(data):
	with open(json_file4, "w") as write_file:
		json.dump(data,write_file)
def write_data_teacher(data):
	with open(json_file2, "w") as write_file:
		json.dump(data,write_file)
def write_data_appointment(data):
	with open(json_file3, "w") as write_file:
		json.dump(data,write_file)

@app.post('/daftar/student')
async def daftar_student(nama : str, password : str):
	max=0
	for data in data_student["student"]:
		if int(data["id"])>max:
			max=int(data["id"])
	max+=1
	data_student['student'].append({"id":max, "name":nama,"password":password})
	data_akun['akun'].append({"akunID":max, "name":nama,"password":password,"role":"student"})
	write_data_student(data_student)
	write_data_akun(data_akun)
	
	return "akun berhasil terbuat"
	
	
@app.get('/appointment/teacher')
async def get_teacher_appointment_list(user: Teacher = Depends(get_curr_user)):
	if isinstance(user, Teacher):
		studentID=user.teacherID
		rows=[]
		for data in data_appointment['appointment']:
			if data['teacherID'] == studentID:
				rows.append([data['studentID'],data['teacherID'],data['tanggal']])
                
		return rows
	else:
		raise HTTPException(status_code=405, detail="unauthorized")
	
@app.get('/appointment/student')
async def get_student_appointment_list(user: Student = Depends(get_curr_user)):
	if isinstance(user, Student):
		studentID=user.studentId
		rows=[]
		for data in data_appointment['appointment']:
			if data['studentID'] == studentID:
				rows.append([data['studentID'],data['teacherID'],data['tanggal']])
                
		return rows
	else:
		raise HTTPException(status_code=405, detail="unauthorized")

