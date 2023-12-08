FROM python:3

ADD main.py .

COPY . /TST-TeachMe
WORKDIR /TST-TeachMe

RUN pip install fastapi uvicorn python-multipart python-jose[cryptography] passlib[bcrypt] requests
CMD ["uvicorn", "main:app", "--host=0.0.0.0", "--port=80"]