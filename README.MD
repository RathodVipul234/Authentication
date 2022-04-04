#Acquaint SoftTech Practical

1.Create virtual environment by bellow one of command
```shell
$ python3 -m venv venv 
$ virtualenv venv -p python3
```

2.Activate your virtual environment
```shell
$ source venv/bin/activate
```

3.Install requirement.txt
```shell
(venv)$ pip install -r requirement.txt 
```

4.Create postgres Database and setup to setting.py

5.Apply migrations
```shell
(venv)$ python3 manage.py makemigrations
(venv)$ python3 manage.py migrate
```

6.Create superuser 
```shell
(venv)$ python3 manage.py createsuperuser
```

7.Add initial category and product by bellow command
```shell
(venv)$ python3 manage.py add_category
(venv)$ python3 manage.py add_products
```

8.Run project on server
```shell
(venv)$ python3 manage.py runserver
```
