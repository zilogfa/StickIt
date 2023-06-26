from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, TelField, BooleanField, TextAreaField, FileField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship

from datetime import datetime


# CONFIGURING FLASK / DATABASE / BCRYPT -------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# CONFIGURING AUTH PREQ ------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# DB TABLES --------------------------------------
with app.app_context():

    class Users(db.Model, UserMixin):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(40), nullable=False)
        username = db.Column(db.String(100), nullable=False, unique=True)
        password = db.Column(db.String(100), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(
            db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        todos = relationship("ToDo", back_populates="parent_user")

        def __repr__(self):
            return f"Image('{self.profileimage}')"

    class ToDo(db.Model):
        __tablename__ = "to_do"
        id = db.Column(db.Integer, primary_key=True)
        todo_id = db.Column(db.Integer, db.ForeignKey(
            "users.id"), nullable=False)
        parent_user = relationship("Users", back_populates="todos")
        todo = db.Column(db.String(250))
        post_time = db.Column(db.String(250))

    db.create_all()


#  WTFORMS _______________________________________


    class ToDoForm(FlaskForm):
        todo = TextAreaField('ToDo', validators=[DataRequired(), Length(
            min=1, max=100)], render_kw={
            "class": "textArea-sec"})
        submit = SubmitField('Add', render_kw={
                             'class': 'btn btn-light', 'style': 'margin:1%'})

    class RegisterForm(FlaskForm):
        name = StringField('Name', validators=[DataRequired()], render_kw={
                           "class": "form-control", "placeholder": "Name *", 'style': 'margin:1%'})
        username = EmailField('Username', validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"class": "form-control", "placeholder": "Username/Email *", 'style': 'margin:1%'})
        password = PasswordField('Password', validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"class": "form-control", "placeholder": "Password *", 'style': 'margin:1%'})
        submit = SubmitField('Register', render_kw={
                             'class': 'btn btn-dark', 'style': 'margin:1%'})

        def validate_user_username(self, username):
            existing_user_username = Users.query.filter_by(
                username=username.data).first()
            if existing_user_username:
                raise ValidationError(
                    "That username already exist. Please choose a diffent one.")

    class LoginForm(FlaskForm):
        username = EmailField('Username', validators=[DataRequired(), Length(
            min=4, max=20)], render_kw={"class": "form-control", "placeholder": "Username", 'style': 'margin:1%'})
        password = PasswordField('Password', validators=[DataRequired(), Length(
            min=4, max=20)], render_kw={"class": "form-control", "placeholder": "Password", 'style': 'margin:1%'})
        submit = SubmitField('Log in', render_kw={
                             'class': 'btn btn-dark', 'style': 'margin:1%'})


# LOGIN / REGISTER / LOGOUT ____________________________________

    @app.route('/', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = Users.query.filter_by(
                username=(form.username.data).lower()).first()
            # Email doesn't exist
            if not user:
                flash("That username does not exist, please try again.")
                return redirect(url_for('login'))

            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    user.updated_at = datetime.utcnow()
                    db.session.commit()
                    return redirect(url_for('home'))

        return render_template('login.html', form=form, logged_in=current_user.is_authenticated)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():

            if Users.query.filter_by(username=form.username.data).first():
                print(Users.query.filter_by(username=form.username.data).first())
                # User already exists
                flash("You've already signed up with that email, log in instead!")
                return redirect(url_for('login'))

            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = Users(
                name=form.name.data,
                username=(form.username.data).lower(),
                password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/logout', methods=['GET', 'POST'])
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))


# HOME PAGE ___________________________


    @app.route('/home', methods=['GET', 'POST'])
    @login_required
    def home():
        form = ToDoForm()
        if form.validate_on_submit():
            print("Form flagged as validate !!! ------")
            new_todo = ToDo(
                parent_user=current_user,
                todo=form.todo.data,
                post_time=datetime.now().strftime("%H:%M · %m/%d/%Y")
            )
            db.session.add(new_todo)
            db.session.commit()
            print('---- New Todo Successfully added to DataBase')
            return redirect(url_for('home'))
        # all_todo = ToDo.query.all()
        all_todos = current_user.todos

        return render_template('index.html', form=form, data=all_todos, logged_in=current_user.is_authenticated)


# EDIT & DELETE  __________________________

    # @app.route('/delete')
    # def delete():
    #     item_id = request.args.get('id')
    #     print(item_id)
    #     todo_to_delete = ToDo.query.get(item_id)
    #     db.session.delete(todo_to_delete)
    #     db.session.commit()
    #     print("------ To DO Deleted from Database: " + str(todo_to_delete))
    #     return redirect(url_for('home'))


    @app.route('/delete/<int:post_id>', methods=['POST'])
    def delete_post(post_id):
        todo_to_delete = ToDo.query.get(post_id)
        db.session.delete(todo_to_delete)
        db.session.commit()
        return redirect(url_for('home'))

    @app.route('/edit-todo/<int:item_id>', methods=["GET", "POST"])
    @login_required
    def edit_todo(item_id):
        # item_id = request.args.get('id')
        todo = ToDo.query.get_or_404(item_id)
        edit_form = ToDoForm(obj=todo)

        if edit_form.validate_on_submit():
            todo.todo = edit_form.todo.data
            db.session.commit()
            return redirect(url_for('home'))

        return render_template('edit.html', form=edit_form, current_user=current_user, edit_page=True, logged_in=current_user.is_authenticated)


# ABOUT __________________________________

    @app.route('/about')
    def about():
        return render_template('about.html', about=True, logged_in=current_user.is_authenticated, current_user=current_user)

    if __name__ == '__main__':
        app.run(debug=True)
