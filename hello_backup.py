from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']="mysql+pymysql://pierre:password123@localhost/users"
app.config['SECRET_KEY'] = "hjhjdgjfgjkvgiorugfrkjbgvndfm,k.hdklkhedfjkbdkjgf h HJW FLhjfkd manmfd,kffvkljhdej"

db = SQLAlchemy(app)
migrate = Migrate(app, db, compare_type=True)


class PasswordForm(FlaskForm):
	email = StringField("What's Your Email", validators=[DataRequired()])
	password_hash = PasswordField("What's Your Password", validators=[DataRequired()])
	submit = SubmitField("Submit")

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True)
    age = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(128))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def password(self):
        raise AttributeError("Password is not a readable Attribute!")
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password=password, method="pbkdf2:sha256")

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


    def __repr__(self):
        return '<Name %r>' % self.name

class Verifier(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(255))

class NamerForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()])
    password_hash=PasswordField(label="Password", validators=[DataRequired(), EqualTo("password_hash2", message="Passwords must match!!")])
    password_hash2 = PasswordField(label="Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    age = IntegerField("Age", validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_two', message='Passwords Must Match!')])
    password_two = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")

class PostForm(FlaskForm):
    title= StringField('Title', validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()], widget=TextArea())
    author = StringField("Author", validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField('Submit')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def index():
    first_name = "Pierre"
    stuff = "This is html <strong>bold</strong> text"
    flash("Welcome to our Website!!")
    favorite_pizza = ["Papperoni", "Cheese", "Mushroom"]
    return render_template('index.html', name=first_name, text=stuff, favorite_pizza=favorite_pizza)

@app.route("/all_users/")
def all_users():
    our_users = Users.query.order_by(Users.date_added)
    return render_template('users.html', our_users=our_users)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route("/form", methods=['GET', 'POST'])
def form():
    name = None
    my_users=None
    form = NamerForm()
    if form.validate_on_submit():
        print(f'Verification: { form.validate_on_submit() }')
    
        email=form.email.data
        password=form.password_hash.data
        user = Verifier(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Form submitted successfully")

    form.email.data=""
    form.password_hash.data = ""
    
    my_users = Verifier.query.all()
    return render_template('form.html', name=name, form=form, my_users=my_users)

@app.route('/user/add', methods=['GET', 'POST'])
def users():
    name= None
    email=None
    age=None
    username=None
    form=UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(password=form.password_hash.data, method="pbkdf2:sha256")
            user = Users(name=form.name.data, username=form.username.data, email=form.email.data, age=form.age.data, password=hashed_pw)
            db.session.add(user)
            db.session.commit()
            flash(f'{form.name.data} Added')
            form.name.data = ""
            form.username.data = ""
            form.email.data = ""
            form.age.data = ""
        else:
            flash('Cannot Add Similar emails')
    form.name.data = ""
    form.email.data = ""
    form.username.data = ""
    form.age.data = ""
    our_users = Users.query.order_by(Users.date_added)
    return render_template("add_user.html", form=form, our_users=our_users)


@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form=UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.age = request.form['age']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User updated Successfuly")
            return redirect(url_for('users'))
            return render_template('update.html', form=form, name_to_update = name_to_update)
        except:
            flash("Error, Looks like there was a problem")
            return render_template('update.html', form=form, name_to_update =name_to_update)
    else:
        return render_template('update.html', form=form, name_to_update = name_to_update, user = name_to_update)

@app.route("/delete/<int:id>")
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name=None
    form=UserForm()

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully")
        our_users = Users.query.order_by(Users.date_added)
        return redirect(url_for('users'))
    except:
        flash('OOps! There was a problem deleting user, try again')
        return redirect(url_for('users'))


@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
    email=None
    password=None
    pw_to_check = None
    passed = None
    password_one=None
    password_one_hash = None
    passed2=None

    form = PasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data
        form.email.data = ''
        form.password_hash.data = ''

        try:
            pw_to_check = Users.query.filter_by(email=email).first()
        except Exception as e:
            print(e)
            redirect(render_template('404.html'))

        passed = check_password_hash(pw_to_check.password_hash, password)

    return render_template("test_pwd.html", 
		email = email,
		password = password,
		pw_to_check = pw_to_check,
		passed = passed,
		form = form,
        password_one=password_one,
        password_one_hash=password_one_hash,
        passed2=passed2
        )


@app.route("/date")
def get_current_date():
    return [{"Dates": ["today", "tomorrow", "yesterday"]}, {"Dates": ["today", "tomorrow", "yesterday"]}, {"Dates": ["today", "tomorrow", "yesterday"]}]


@app.route("/add-post", methods=['GET', "POST"])
def add_post():
    form=PostForm()

    if form.validate_on_submit():
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data, slug=form.slug.data)
        form.title.data = ""
        form.content.data = ""
        form.author.data = ""
        form.slug.data = ""

        db.session.add(post)
        db.session.commit()

        flash("Blog post submitted successfully")

    return render_template('add_post.html', form=form)


@app.route("/posts")
def posts():
    posts = Posts.query.order_by(Posts.date)
    return render_template("posts.html", posts=posts)


@app.route("/posts/<int:id>")
def post(id):
    post = Posts.query.get_or_404(id)

    return render_template("post.html", post=post)


@app.route("/posts/edit/<int:id>", methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form=PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data

        db.session.add(post)
        db.session.commit()
        flash("Post has been updated!")

        return redirect(url_for('post', id=post.id))

    form.title.data = post.title
    form.author.data = post.author
    form.slug.data = post.slug
    form.content.data = post.content

    return render_template('edit_post.html', form=form)


@app.route("/posts/delete/<int:id>")
@login_required
def delete_post(id):
    post_to_delete=Posts.query.get_or_404(id)
    
    try:
        db.session.delete(post_to_delete)
        db.session.commit()
        flash('Post deleted successfully')
        posts = Posts.query.order_by(Posts.date)
        return render_template("posts.html", posts=posts)
    except:
        flash('Ooops! Problem deleting post')

        posts = Posts.query.order_by(Posts.date)
        return render_template("posts.html", posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        print(user, user.password_hash)
        if user:
            # tseting my user authentication not working
            if not check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                form.username.data = ""
                flash("Login successful")
                return redirect(url_for('dashboard'))
            else:
                form.username.data = ""
                flash('Wrong Password Try again')
        else:
            flash(f"User {form.username.data} does not exist!!")
            form.username.data = ""
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form=UserForm()
    id=current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.age = request.form['age']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User updated Successfuly")
            return render_template('dashboard.html', form=form, name_to_update = name_to_update)
        except:
            flash("Error, Looks like there was a problem")
            return render_template('dashboard.html', form=form, name_to_update =name_to_update)
    else:
        return render_template('dashboard.html', form=form, name_to_update = name_to_update, user = name_to_update)

    return render_template('dashboard.html', form=form)


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out! Thanks for passing By")
    return redirect(url_for('login'))




# if __name__=="__main__":
#     db.create_all()
#     app.run(port=8000, debug=True)
