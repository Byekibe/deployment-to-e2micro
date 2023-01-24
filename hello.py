from flask import Flask, render_template, flash, request, redirect, url_for
from forms import PasswordForm, NamerForm, UserForm, PostForm, LoginForm, SearchForm
from werkzeug.security import generate_password_hash, check_password_hash
from models import Users, db, app, Posts, Verifier
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor
from flask_ckeditor import CKEditorField

ckeditor = CKEditor(app)

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
@login_required
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
        return render_template('update.html', form=form, name_to_update = name_to_update, user = name_to_update, id=id)

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
        poster = current_user.id
        post = Posts(title=form.title.data, content=form.content.data, poster_id=poster, slug=form.slug.data)
        form.title.data = ""
        form.content.data = ""
        form.slug.data = ""

        db.session.add(post)
        db.session.commit()

        flash("Blog post submitted successfully")

    return render_template('add_post.html', form=form)


@app.route("/posts")
def posts():
    try:
        poster = current_user.id
        posts = Posts.query.order_by(Posts.date)
        return render_template("posts.html", posts=posts, poster=poster)
    except Exception as e:
        flash('You must login to view this page!!')
        return redirect(url_for('login'))


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
        post.slug = form.slug.data
        post.content = form.content.data

        db.session.add(post)
        db.session.commit()
        flash("Post has been updated!")
        return redirect(url_for('post', id=post.id))
    if current_user.id == post.poster_id:
        form.title.data = post.title
        form.slug.data = post.slug
        form.content.data = post.content
        return render_template('edit_post.html', form=form)
    else:
        flash("You aren't authorized to edit this post")
        post = Posts.query.get_or_404(id)
        return render_template("post.html", post=post)


@app.route("/posts/delete/<int:id>")
@login_required
def delete_post(id):
    post_to_delete=Posts.query.get_or_404(id)
    id=current_user.id
    if id == post_to_delete.poster.id:
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
    else:
        flash('Ooops! You can\'t delete the post. You don\'t have permission!')
        posts = Posts.query.order_by(Posts.date)
        return render_template("posts.html", posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # testing my user authentication not working
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

@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)

@app.route("/search", methods=['POST'])
def search():
    form=SearchForm()
    posts = Posts.query
    if form.validate_on_submit():
        post.searched = form.searched.data
        posts = posts.filter(Posts.content.like('%' + post.searched + '%'))
        posts = posts.order_by(Posts.title).all()

    return render_template('search.html', form=form, searched=post.searched, posts=posts)

@app.route("/admin")
@login_required
def admin():
    id = current_user.id
    if id == 70:
        return render_template('admin.html')
    else:
        flash('You Must Be an Admin to access this site')
        return redirect(url_for('dashboard'))




# if __name__=="__main__":
#     db.create_all()
#     app.run(port=8000, debug=True)