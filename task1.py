from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from forms import LoginForm
import re
import psycopg2

# engine = create_engine('postgresql+psycopg2://myuser:mypass@hostname/postgres')

app = Flask(__name__)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://myuser:mypass@localhost:5432/postgres"
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)  # buralar değişcek

conn = psycopg2.connect(
    database="postgres", user='myuser', password='mypass', host='127.0.0.1', port='5432'
)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True
    )

    firstname = db.Column(
        db.String(100),
        unique=False
    )

    middlename = db.Column(
        db.String(100),
        unique=False
    )

    lastname = db.Column(
        db.String(100),
        unique=False
    )

    birthdate = db.Column(
        db.Date,
        unique=False
    )

    email = db.Column(
        db.String(100),
        unique=True
    )

    password_hash = db.Column(
        db.String(128)
    )

    ipaddress = db.Column(
        db.String(100),
        unique=False
    )

    logindatetime = db.Column(
        db.DateTime,
        unique=False
    )

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __init__(self, username, firstname, middlename, lastname, birthdate, email, password_hash, ipaddress,
                 logindatetime):
        self.username = username
        self.firstname = firstname
        self.middlename = middlename
        self.lastname = lastname
        if birthdate == '':
            self.birthdate = ''
        else:
            self.birthdate = datetime.strptime(birthdate, '%Y-%m-%d')
            self.birthdate = self.birthdate.date()
        # self.birthdate = datetime.strptime(birthdate, '%d-%m-%Y')
        self.email = email
        self.password_hash = password_hash
        self.ipaddress = ipaddress
        self.logindatetime = logindatetime

    def initOthers(self, ipaddress, logindatetime):
        self.ipaddress = ipaddress
        self.logindatetime = logindatetime

    """
    def set_password(self, password):
        self.password = generate_password_hash(
            password,
            method='sha256'
        )

    def check_password(self, password):
        return check_password_hash(self.password, password)
    """

    def __repr__(self):
        return '<User {}>'.format(self.username)


first = True


@app.route('/')
def home():
    global first
    if first:
        with open('log.txt', 'a') as f:
            f.write('\n-----------------------------------\n\n')
        first = False
    with open('log.txt', 'a') as f:
        f.write('Entered Home Page\n')

    return render_template("baseFT.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    """
    login olmak için kullanılır.
    :return:  hesabınız yoksa ilk önce create etmeniz gerekir. eğer hesabınız varsa ve başarılı şekilde geçerseniz user'a atar.
    """
    with open('log.txt', 'a') as f:
        f.write('Entered Login Page\n')

    form = LoginForm()
    username = form.username.data
    if form.validate_on_submit():
        form.username.data = ''
        boolValue, password = isThisUsernameExist(username)
        if boolValue:
            # user.initOthers(request.remote_addr, datetime.now())

            # db.session.commit()

            bosluksuz = password.strip(' ')

            if check_password_hash(bosluksuz, form.password.data):
                data = [username, request.remote_addr]
                if not contains(1, username):
                    insert(1, data)
                else:
                    updateTable(1, data, "")

                with open('log.txt', 'a') as f:
                    f.write(username + ' Logged In!\n')

                session["username"] = username
                form.password.data = ''
                return redirect(url_for("user"))
            else:
                with open('log.txt', 'a') as f:
                    f.write(username + ' Entered Wrong Password!\n')
                flash("Wrong Password - Try Again!")
        else:
            with open('log.txt', 'a') as f:
                f.write('Tried to login an account that does not exist!\n')
            flash("That User Doesn't Exist! Try Again...")

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """
    eger logout olmak isteyen kullanıcı session'da ise session'dan ve onlineusers tablosundan o kullanıcıyı çıkartır
    """
    if "username" in session:
        username = session["username"]
        with open('log.txt', 'a') as f:
            f.write(username + ' Logged Out!\n')
        session.pop("username", None)
        if contains(1, username):
            deleteFromTable(1, username)

    return redirect(url_for("login"))


@app.route('/user')
def user():
    """
    eger bu kullanıcı şu an session'da ise websiteye gider yoksa login olmasını ister
    """
    with open('log.txt', 'a') as f:
        f.write('Entered user!\n')

    if "username" in session:
        username = session["username"]
        with open('log.txt', 'a') as f:
            f.write(username + '\'s page\n')
        id = findId(username)
        return render_template('website.html', context=username, id=id)
    else:
        flash("You are not logged in. Please login first.")
        return redirect(url_for("login"))


@app.route('/user/list')
def list():
    """
    eger bu kullanıcı şu an session'da ise websiteye gider yoksa login olmasını ister
    """
    if "username" in session:
        with open('log.txt', 'a') as f:
            f.write(session["username"] + ' looked to list!\n')
        users = findAll(0)
        return render_template('list.html', users=users)
    else:
        flash("You are not logged in. Please login first to see users.")
        return redirect(url_for("login"))


@app.route('/user/create', methods=["POST", "GET"])
def create():
    """
    yeni kullanıcı oluşturmak için kullanılır.
    :return: işlem başarılı ise login'e, yoksa bu sayfada kalmaya devam edersiniz.
    """
    with open('log.txt', 'a') as f:
        f.write('Entered Create\n')

    if request.method == "POST":
        username = request.form["un"]
        firstname = request.form["fn"]
        middlename = request.form["mn"]
        lastname = request.form["ln"]
        birthdate = request.form["bd"]
        email = request.form["e"]
        password = request.form["pw"]

        password_hashed = generate_password_hash(password)

        new_user = User(
            username=username,
            firstname=firstname,
            middlename=middlename,
            lastname=lastname,
            birthdate=birthdate,
            email=email,
            password_hash=password_hashed,
            ipaddress='',
            logindatetime=None
        )

        data = [username, firstname, middlename, lastname, birthdate, email, password]

        errorMessage = isValidUsername(username)
        errorMessage2 = isValidEmail(email)

        data2 = ["username", "firstname", "middlename", "lastname", "birthdate", "email", "password"]

        for x in range(len(data)):
            if data[x] == "":
                flash(data2[x] + " cannot be empty")

                with open('log.txt', 'a') as f:
                    f.write('Try to leave' + data2[x] + ' blank \n')
                return render_template("validCheck.html", nameToCheck=new_user)

        if errorMessage != "True":
            flash(errorMessage)
            with open('log.txt', 'a') as f:
                f.write('Wrong username attempt during account creation\n')
            return render_template("validCheck.html", nameToCheck=new_user)

        if errorMessage2 != "True":
            flash(errorMessage2)
            with open('log.txt', 'a') as f:
                f.write('Wrong email attempt during account creation\n')
            return render_template("validCheck.html", nameToCheck=new_user)

        if not isValidPassword(password):
            with open('log.txt', 'a') as f:
                f.write('Wrong password attempt during account creation\n')
            flash(
                "Flash message. Wrong password format! It should be min 8 length. Also, it should contains at least one uppercase letter, one lowercase letter and one number.")
            return render_template("validCheck.html", nameToCheck=new_user)
        else:
            insert(0, new_user)
            # db.session.add(new_user, "")  # Adds new User record to database
            # db.session.commit()  # Commits all changes

            with open('log.txt', 'a') as f:
                f.write(username + ' is created!\n')

            return redirect(url_for("login"))
    else:
        return render_template("create.html")


@app.route('/user/delete/<id>')
def delete(id):
    """
    alınan id'yi ve biligleri silmek için kullanılır.
    :param id: silmek istediğimiz kullanıcının id'si.
    :return: login'e atar.
    """
    if "username" in session:
        with open('log.txt', 'a') as f:
            f.write('Entered Delete\\' + id + '\n')

        user = findUsername(id)
        username = user[1]
        bosluksuz = username.strip(' ')
        asd = session["username"]

        if asd == bosluksuz:

            session.pop("username", None)

            deleteFromTable(0, username)
            deleteFromTable(1, username)

            flash(username + " deleted successfully!")
            return redirect(url_for("login"))
        else:
            flash("You should login first to delete an account.")
            return redirect(url_for("user"))

    else:
        flash("You are not logged in. Please login first to see users.")
        return redirect(url_for("login"))


@app.route('/user/update/<id>', methods=["POST", "GET"])
def update(id):
    """
    alınan id'deki bilgileri güncellemek için kullanılır.
    :param id: güncellemek istediğimiz kullanıcının id'si.
    :return: update.html'e atar.
    """
    with open('log.txt', 'a') as f:
        f.write('Entered Update\\' + id + '\n')

    nameToUpdate = findUsername(id)
    if request.method == "POST":
        if "username" in session:
            prevUsername = session["username"]
            demoUser = [*nameToUpdate, ]
            # demoUser = list(nameToUpdate)

            demoUser[1] = request.form["un"]
            demoUser[2] = request.form["fn"]
            demoUser[3] = request.form["mn"]
            demoUser[4] = request.form["ln"]

            birthdate = request.form["bd"]
            demoUser[5] = datetime.strptime(birthdate, '%Y-%m-%d')

            demoUser[6] = request.form["e"]
            password = request.form["pw"]
            demoUser[7] = generate_password_hash(password)
            nameToUpdate = tuple(demoUser)

            data = [demoUser[1], demoUser[2], demoUser[3], demoUser[4], demoUser[5], demoUser[6], demoUser[7]]
            data2 = ["username", "firstname", "middlename", "lastname", "birthdate", "email", "password"]

            for x in range(len(data)):
                if data[x] == "":
                    flash(data2[x] + " cannot be empty")

                    with open('log.txt', 'a') as f:
                        f.write('Try to leave' + data2[x] + ' blank \n')
                    return render_template("update.html", nameToUpdate=nameToUpdate)

            prevEmail = findEmail(prevUsername)

            errorMessage = isValidUsernameUpdate(demoUser[1])
            errorMessage2 = isValidEmailUpdate(demoUser[6], prevEmail)

            if errorMessage != "True":
                flash(errorMessage)
                with open('log.txt', 'a') as f:
                    f.write('Wrong username attempt during account creation\n')
                return render_template("update.html", nameToUpdate=nameToUpdate)
            session["username"] = demoUser[1]
            if errorMessage2 != "True":
                flash(errorMessage2)
                with open('log.txt', 'a') as f:
                    f.write('Wrong email attempt during account creation\n')
                return render_template("update.html", nameToUpdate=nameToUpdate)

            if not isValidPassword(password):
                with open('log.txt', 'a') as f:
                    f.write('Wrong password attempt during account creation\n')
                flash(
                    "Flash message. Wrong password format! It should be min 8 length. Also, it should contains at least one uppercase letter, one lowercase letter and one number.")
                return render_template("update.html", nameToUpdate=nameToUpdate)
            else:
                updateTable(0, nameToUpdate, "")
                onlineUserToUpdate = [prevUsername, request.remote_addr]
                if prevUsername != demoUser[1]:
                    updateTable(1, onlineUserToUpdate, demoUser[1])
                flash("Updated successfully!")
                return render_template("update.html", nameToUpdate=nameToUpdate)
        else:
            flash("username is not in session! Try to rerun the project")
            return redirect(url_for("login"))
    else:
        return render_template("update.html", nameToUpdate=nameToUpdate)


@app.route('/onlineusers')
def onlineusers():
    """
    ilk önce login olunması gereklidir. Login olanları gösterir.
    :return: log,n olunmadıysa login page'ine atar. olunduysa kullanıcıları gösteren page'e atar.
    """
    if "username" in session:
        with open('log.txt', 'a') as f:
            f.write('Entered onlineusers\n')
        users = findAll(1)
        return render_template("onlineList.html", users=users)
    else:
        flash("You are not logged in. Please login first to see online users.")
        return redirect(url_for("login"))


@app.route('/user/print')
def printUsers():
    """
    users tablosunu json data formatında bastırır
    :return: users tablosunu json data formatında döndürür.
    """
    users = findAll(0)
    data = []
    for user in users:
        userJson = [
            {'username': user[1], 'firstname': user[2], 'middlename': user[3],
             'lastname': user[4], 'birthdate': user[5], 'email': user[6],
             'password_hash': user[7]}
        ]
        data.append(userJson)

    return jsonify(data)


@app.route('/onlineusers/print')
def printOnlineusers():
    """
    onlineUsers tablosunu json data formatında bastırır
    :return: onlineUsers tablosunu json data formatında döndürür.
    """
    users = findAll(1)
    data = []
    for user in users:
        userJson = [
            {'username': user[0], 'ipaddress': user[1], 'logindatetime': user[2]}
        ]
        data.append(userJson)

    return jsonify(data)


@app.errorhandler(404)
def page_not_found(e):
    """
    yazılan route'lardan başka route girilirse buraya gelir.
    """
    with open('log.txt', 'a') as f:
        f.write('Entered non exist page\n')
    return render_template("404.html"), 404


def isValidUsername(username):
    """
    alınan username formata uyuyor mu ve önceden var mı kontrolu yapar.
    :param username: kontrolu yapılacak username.
    :return: username alındıysa ilk return, formata uygun değilse ikinci return, her şey doğruysa da True döner.
    """
    users = findAll(0)
    for user in users:
        bosluksuz = user[1].strip(' ')
        if username == bosluksuz:
            return "This username is taken."

    pattern = re.compile("^(.*\s+.*)+$")
    if pattern.match(username):
        return "Username cannot contains white space."
    else:
        return "True"


def isValidUsernameUpdate(username):
    """
    :param username:
    :return:
    """
    asd = session["username"]
    bosluksuz2 = asd.strip(' ')
    users = findAll(0)
    for user in users:
        bosluksuz = user[1].strip(' ')
        if username == bosluksuz and username != bosluksuz2:
            return "This username is taken."

    pattern = re.compile("^(.*\s+.*)+$")
    if pattern.match(username):
        return "Username cannot contains white space."
    else:
        return "True"


def isValidEmail(email):
    """
    alınan emial formata uyuyor mu ve önceden var mı kontrolu yapar.
    :param email: kontrolu yapılacak email.
    :return: email alındıysa ilk return, formata uygun değilse ikinci return, her şey doğruysa da True döner.
    """
    users = findAll(0)
    for user in users:
        bosluksuz = user[6].strip(' ')
        if email == bosluksuz:
            return "This email is taken."
    pattern = re.compile("^([a-zA-Z0-9._]*)@([a-zA-Z]*)\.([a-zA-Z]*)")
    if pattern.match(email) is None:
        return "Email format is not correct!."
    else:
        return "True"


def isValidEmailUpdate(email, prevEmail):
    """
    isValidEmail ile aynı işlemi yapar ancak update'te yapıldığı için halihazırda olan mailler aynı olmama koşulu da vardır.
    :param email: kontrolu yapılacak email.
    :param prevEmail: değişmeden önceki email
    :return:
    """
    users = findAll(0)
    bosluksuz2 = prevEmail.strip(' ')
    for user in users:
        bosluksuz = user[6].strip(' ')
        if email == bosluksuz and email != bosluksuz2:
            return "This email is taken."
    # falsk fonkuna bak email valid için
    pattern = re.compile("^([a-zA-Z0-9._]*)@([a-zA-Z]*)\.([a-zA-Z]*)")
    # pattern = re.compile("^[\w._%+-]+@[\w.-]+\.[a-zA-Z]*$")
    if pattern.match(email) is None:
        return "Email format is not correct!."
    else:
        return "True"


def isValidPassword(password):
    """
    alınan password'ün istenilen formata uygun olup olmadığını kontrol eder.
    :param password: kotrnol edilmesi istenen password
    :return:
    """
    pattern = re.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d#?!@$%^&*-+/]{8,}$")
    return pattern.match(password)


def createTable(mod):
    """
    alınan mod'a göre o tabloyu oluşturur, eğer varsa yeniden oluşturmaz.
    :param mod: 0 ise users üzerinde, 1 ise onlineusers üzerinde işlem yapar.
    """
    cursor = conn.cursor()

    if mod == 0:
        cursor.execute('CREATE TABLE if not exists users ('
                       '"id" SERIAL PRIMARY KEY,'
                       '"username" CHAR(50) UNIQUE,'
                       '"firstname" CHAR(100),'
                       '"middlename" CHAR(100),'
                       '"lastname" CHAR(100),'
                       '"birthdate" DATE,'
                       '"email" CHAR(100) UNIQUE,'
                       '"password_hash" CHAR(128));'
                       )
    else:
        cursor.execute('CREATE TABLE if not exists onlineUsers ('
                       '"username" CHAR(50) PRIMARY KEY,'
                       '"ipaddress" INET,'
                       '"logindatetime" timestamp);'
                       )
    conn.commit()


def insert_stmt(mod):
    """
    insert işlemini yapmak için gereken statement
    :param mod: 0 ise users üzerinde, 1 ise onlineusers üzerinde işlem yapar.
    :return:
    """
    if mod == 0:
        return """INSERT INTO users (id ,username, firstname, middlename, lastname, birthdate, email, password_hash) VALUES (DEFAULT, %s, %s, %s, %s, %s, %s, %s);"""
    else:
        return """INSERT INTO onlineUsers (username, ipaddress, logindatetime) VALUES ('{0}', '{1}', '{2}');"""


def insert(mod, user):
    """
    istenen tabloya alınan user'i ekler.
    :param mod: 0 ise users üzerinde, 1 ise onlineusers üzerinde işlem yapar.
    :param user: tabloya eklenmesini istediğimiz user
    """
    cursor = conn.cursor()

    if mod == 0:
        data = (
            user.username, user.firstname, user.middlename, user.lastname, user.birthdate, user.email,
            user.password_hash)
        # cursor.execute(insert_stmt(0).format(data[0], data[1], data[2], data[3], data[4], data[5], data[6]))
        cursor.execute(insert_stmt(0), data)
    else:
        t = datetime.now()
        t = t.strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(insert_stmt(1).format(user[0], user[1], t))

    conn.commit()


def contains(mod, username):
    """
    verilen username istenen tabloda var mı yok mu kontrolu yapar.
    :param mod: 0 ise users, 1 ise onlineusers üzerinde işlem yapar.
    :param username: kontrol edilmesi istenen username.
    :return: username tabloda varsa True, yoksa False döner.
    """
    cursor = conn.cursor()
    if mod == 0:
        cursor.execute("SELECT * FROM users WHERE username = '{0}';".format(username))
        for x in cursor.fetchall():
            return True
        return False
    else:
        cursor.execute("SELECT * FROM onlineUsers WHERE username = '{0}';".format(username))
        for x in cursor.fetchall():
            return True
        return False


def deleteFromTable(mod, username):
    """
    alınan parametrelere göre kullanıcıyı tablodan kaldırır.
    :param mod: 0 ise users, 1 ise onlineusers üzerinde işlem yapmamızı sağlar.
    :param username: tablodan silinmesi istenen username.
    """
    cursor = conn.cursor()
    if mod == 0:
        cursor.execute("DELETE FROM users WHERE username = '{0}';".format(username))
    else:
        cursor.execute("DELETE FROM onlineUsers WHERE username = '{0}';".format(username))
    conn.commit()


def findAll(mod):
    """
    fonksiyon ne işe yarıyor
    :param mod: 1 ise şu 2 ise bu
    :return: integer (1 , 2)
    """
    cursor = conn.cursor()
    if mod == 0:
        cursor.execute("SELECT * FROM users")
    else:
        cursor.execute("SELECT * FROM onlineUsers")
    data = cursor.fetchall()
    for x in data:
        print(x)

    return data


def findId(username):
    """
    verilen username ile işleşen id'yi döner
    :param username: id'i bulunmasını istenen username idir.
    :return: bulursa id'yi, bulamazsa -1 döner.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '{0}';".format(username))

    for x in cursor.fetchall():
        return x[0]

    return -1


def findEmail(username):
    """
    verilen username ile işleşen email'i döner
    :param username: email'i bulunmasını istenen username idir.
    :return: bulursa emiali, bulamazsa -1 döner.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '{0}';".format(username))

    for x in cursor.fetchall():
        return x[6]

    return -1


def findUsername(id):
    """
    verilen id ile işleşen username'i döner
    :param id: username'i bulunmasını istenen id idir.
    :return: bulursa ismi, bulamazsa -1 döner.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = '{0}';".format(id))

    for x in cursor.fetchall():
        return x

    return -1


def isThisUsernameExist(username):
    """
    verilen username mevcut mu diye kontrol eder.
    :param username: bu username users tablosunda mevcut mu diye bakar
    :return: eğer varsa True ve kullanıcının şifresini döner. Yoksa False ve -1 döner
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '{0}';".format(username))

    for x in cursor.fetchall():
        password = x[7]
        return True, password

    return False, -1


def updateTable(mod, user, newUsername):
    """
    alınan parametrelere göre tabloyu değiştirir.
    :param mod: eğer mod 0 ise users tablosuna 1 ise onlineusers tablosuna işlem yapılır
    :param user: işlem yapılacak user
    :param newUsername: bu parametre sadece update yaparken önemlidir. kullanıcı mevcut username'ini değiştirmek isterse kullanılır.
    """
    cursor = conn.cursor()
    if mod == 0:
        data = (user[1], user[2], user[3], user[4], user[5], user[6], user[7], user[0])
        cursor.execute(
            "UPDATE users SET username = %s, firstname = %s, middlename = %s, lastname = %s, birthdate = %s, email = %s, password_hash = %s WHERE id = %s",
            data)
    else:
        if newUsername == "":
            t = datetime.now()
            t = t.strftime('%Y-%m-%d %H:%M:%S')
            data = (user[1], t, user[0])

            cursor.execute(
                "UPDATE onlineUsers SET ipaddress = %s, logindatetime = %s WHERE username = %s", data)
        else:
            t = datetime.now()
            t = t.strftime('%Y-%m-%d %H:%M:%S')

            data = (user[1], t, user[0])

            data2 = (newUsername, t)
            cursor.execute("UPDATE onlineUsers SET ipaddress = %s, logindatetime = %s WHERE username = %s", data)
            cursor.execute("UPDATE onlineUsers SET username = %s WHERE logindatetime = %s", data2)

    conn.commit()


if __name__ == "__main__":
    # with app.app_context():
    #    db.create_all()
    createTable(0)
    createTable(1)
    app.run()
