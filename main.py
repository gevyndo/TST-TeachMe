import json
from typing import Annotated
from fastapi import Depends, Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Union
import requests
admin_db={
	"admin":{
		"id":-3,
		"username":"admin",
		"password_hashed":"$2b$12$E.Meix7tEEB5yYOWiYNbBO0jHkQNLMrObupNQOSMxC7Ve4y3E2.7i",
		"role":"admin"
	}
}

class Admin:
	def __init__(self, id, name, password, role):
		self.id=id
		self.name = name
		self.password = password
		self.role=role

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

class TeacherEdit(BaseModel):
	name:str
	teacherID:int
	spesialisasi:str

class StudentEdit(BaseModel):
	name:str
	id:int
	password:str

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

app = FastAPI()
json_file='student.json'
json_file2='teacher.json'
json_file3='appointment.json'
json_file4='akun.json'

oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
	return pwd_context.verify(plain_password, hashed_password)

def get_password_hashed(password):
	return pwd_context.hash(password)

with open(json_file,'r') as read:
	data_student=json.load(read)

with open(json_file2,'r') as read:
	data_teacher=json.load(read)

with open(json_file3,'r') as read:
	data_appointment=json.load(read)
with open(json_file4,'r') as read:
	data_akun=json.load(read)

def authenticate_user(username:str,password:str):
	if username == 'admin':
		if verify_password(password,admin_db["admin"]["password_hashed"]):
			admin = User(name=username,password=admin_db["admin"]["password_hashed"],id=-3,role='admin')
			return admin
	user_correct=False
	for data in data_akun["akun"]:
		if username == data["name"] and verify_password(password,data['password']):
			user_correct = True
			user = User(name=data["name"],password=data["password"],id=data["akunID"],role=data["role"])
			return user
	if not user_correct:
		raise HTTPException(status_code=401, detail="Invalid Username r Password")

def update_teacher_data(data):
    with open('teacher.json', 'w') as file:
        json.dump(data, file)	

async def get_curr_user(token : str = Depends(oauth_scheme)):
	payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
	if payload.get('role') == 'admin':
		user = Admin(id=-3,name="admin",password="$2b$12$E.Meix7tEEB5yYOWiYNbBO0jHkQNLMrObupNQOSMxC7Ve4y3E2.7i",role="admin")
		return user
	elif payload.get('role') == "teacher":
		try:
			for data in data_teacher["teacher"]:
				if payload.get("id") == data["teacherID"]:
					user = Teacher(name = payload.get("name"), teacherID=payload.get("id"),spesialisasi="game")
					return user
		except:
			raise HTTPException(status_code=401, detail="Invalid Username r Password")
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
	token = jwt.encode({'username':user.name,'id':user.id, 'role':user.role}, SECRET_KEY)
	return {"access_token": token, "token_type":"bearer"}

@app.get('/all/teacher')
async def get_all_teacher(user: Student = Depends(get_curr_user)):
	if isinstance(user, Student) or isinstance(user,Admin):
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


@app.get('/all/akun')
async def get_all_akun(user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		return data_akun['akun']
	else:
		raise HTTPException(status_code=405, detail="unauthorized")

@app.get('/all/teacher')
async def get_all_teacher(user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		return data_teacher['teacher']
	else:
		raise HTTPException(status_code=405, detail="unauthorized")

@app.get('/all/appointment')
async def get_all_appointment(user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		return data_appointment['appointment']
	else:
		raise HTTPException(status_code=405, detail="unauthorized")
	
@app.get('/all/student')
async def get_all_student(user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		return data_student['student']
	else:
		raise HTTPException(status_code=405, detail="unauthorized")

@app.get('/all/appointment/{id}')
async def get_appointment(id:int, user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		rows=[]
		for data in data_appointment['appointment']:
			if data['id'] == id:
				return data

		raise HTTPException(status_code=401, detail="id not found")     
		
	else:
		raise HTTPException(status_code=405, detail="unauthorized")


@app.post('/daftar/student')
async def daftar_student(riwayatPenyakit :str,nama : str, password : str):
	max=0
	for data in data_student["student"]:
		if int(data["id"])>max:
			max=int(data["id"])
	max+=1
	password_hashed=get_password_hashed(password)
	url = 'tugasghaylan.a9gec8gtbgekdqcz.southeastasia.azurecontainer.io/daftar'
	headers = {
		'accept':'application/json',
		'Content-Type': 'application/x-www-form-urlencoded'
	}
	data = {
		"nama": nama,
		"riwayatPenyakit":riwayatPenyakit
	}
	response = requests.post(url,headers=headers, data=data)
	if response.status_code==200:
		print(response)
		id = 0
		for karakter in response.text:
			if karakter.isdigit():
				id=id*10 + int(karakter)
		url = 'tugasghaylan.a9gec8gtbgekdqcz.southeastasia.azurecontainer.io/users'
		headers = {
			'accept':'application/json',
			'Content-Type': 'application/x-www-form-urlencoded'
		}
		data = {
			"username": nama,
			"password":password,
			"patientId":id
		}
		response = requests.post(url,headers=headers, data=data)
		if response.status_code==200:
			result=response.json()
			data_student['student'].append({"id":max, "name":nama,"password":password_hashed,"token": result.get('access_token')})
			data_akun['akun'].append({"akunID":max, "name":nama,"password":password_hashed,"role":"student"})
			write_data_student(data_student)
			write_data_akun(data_akun)
			return "akun berhasil terbuat"
	

@app.put('/edit/teacher')
async def edit_teacher(teacher:TeacherEdit,user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		teacher_dict=teacher.dict()
		item_found = False
		for teacher_idx, teacher_item in enumerate(data_teacher['teacher']):
			if teacher_item['teacherID'] == teacher_dict['teacherID']:
				item_found = True
				data_teacher['teacher'][teacher_idx]=teacher_dict
				
				with open(json_file2,"w") as write_file:
					json.dump(data_teacher, write_file)
				return "Updated"
	else:
		raise HTTPException(status_code=405, detail="unauthorized")	

@app.put('/edit/student')
async def edit_student(student:StudentEdit,user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		student_dict=student.dict()
		item_found = False
		for student_idx, student_item in enumerate(data_student['student']):
			if student_item['id'] == student_dict['id']:
				item_found = True
				data_student['student'][student_idx]=student_dict
				
				with open(json_file,"w") as write_file:
					json.dump(data_student, write_file)
				return "Updated"
	else:
		raise HTTPException(status_code=405, detail="unauthorized")	

@app.get('/appointment/teacher')
async def get_teacher_appointment_list(user: Teacher = Depends(get_curr_user)):
	if isinstance(user, Teacher):
		studentID=user.teacherID
		rows=[]
		for data in data_appointment['appointment']:
			if data['teacherID'] == studentID:
				rows.append([data['studentID'], data['teacherID'], data['tanggal']])              
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

@app.delete('/teacher/{teacher_id}')
async def delete_teacher(teacher_id: int,user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		item_found = False
		for teacher_idx, teacher_item in enumerate(data_teacher['teacher']):
			if teacher_item['teacherID'] == teacher_id:
				item_found = True
				data_teacher['teacher'].pop(teacher_idx)
				
				with open(json_file2,"w") as write_file:
					json.dump(data_teacher, write_file)
				return "Deleted"
	
		if not item_found:
			return "teacher ID not found."
		raise HTTPException(
			status_code=404, detail=f'item not found'
		)
	else:
		raise HTTPException(
			status_code=401, detail=f'unauthorized'
		)
@app.delete('/student/{student_ID}')
async def delete_teacher(student_ID: int,user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		item_found = False
		for teacher_idx, teacher_item in enumerate(data_student['student']):
			if teacher_item['id'] == student_ID:
				item_found = True
				data_student['student'].pop(teacher_idx)
				
				with open(json_file,"w") as write_file:
					json.dump(data_student, write_file)
				return "Deleted"
	
		if not item_found:
			return "student ID not found."
		raise HTTPException(
			status_code=404, detail=f'item not found'
		)
	else:
		raise HTTPException(
			status_code=401, detail=f'unauthorized'
		)

@app.post('/add/teacher')
async def add_teacher(nama:str,password:str,spesialiasi:str,user: Admin = Depends(get_curr_user)):
	if isinstance(user, Admin):
		max=0
		for data in data_teacher["teacher"]:
			if int(data["teacherID"])>max:
				max=int(data["teacherID"])
		max+=1
		password_hashed=get_password_hashed(password)
		data_teacher['teacher'].append({"name": nama, "teacherID": max, "spesialiasi": spesialiasi})
		data_akun['akun'].append({"akunID":max, "name":nama,"password":password_hashed,"role":"teacher"})
		write_data_teacher(data_teacher)
		write_data_akun(data_akun)
		
		return "akun berhasil terbuat"
	else:
		raise HTTPException(status_code=405, detail="unauthorized")

@app.post('/makeappointment')
async def add_appointment(tekananDarah:int, tinggiBadan:int, beratBadan:int, teacherID:int, tanggal:str,user:Union[Admin, Student] = Depends(get_curr_user) ):
	if isinstance(user, Admin) or isinstance(user, Student):
		max=0
		for data in data_appointment["appointment"]:
			if int(data["id"])>max:
				max=int(data["id"])
		max+=1


		if isinstance(user,Student):
			data_appointment['appointment'].append({"id":max,"studentID":user.studentId,"teacherID":teacherID,"tanggal":tanggal})
			write_data_appointment(data_appointment)
		else:
			data_appointment['appointment'].append({"id":max,"studentID":user.id,"teacherID":teacherID,"tanggal":tanggal})
			write_data_appointment(data_appointment)
		return "appointment berhasil dibuat"

@app.get('/rekomendasi')
async def get_rekomendasi(topik:str,user:Union[Admin, Student] = Depends(get_curr_user) ):
	if isinstance(user, Admin) or isinstance(user, Student):
		hasil=[]
		for data in data_teacher["teacher"]:
			if topik.lower() == data["spesialisasi"].lower():
				hasil.append(data)
		return hasil
		
		
		