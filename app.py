from datetime import datetime
#from PIL import Image
from flask import Flask, render_template, redirect, request, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length



app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///app_data.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'Login'

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_h = db.Column(db.String(8))
    image_file = db.Column(db.String(20), nullable=False, default='static/newpost.png')
    posts = db.relationship('Post', backref='author', lazy=True)
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    def __repr__(self):
        return f'Username: {self.username}'
    
    def set_password(self, password):
        self.password_h = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_h, password)


class Community(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), index=True, unique=True)
    desc = db.Column(db.String(200), index=True, unique=True)

    #def __repr__(self):
        #return f'''
        #Community name: {self.name}\nDescription: {self.desc}
        

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    image = db.Column(db.Text, nullable=True)
    video_audio = db.Column(db.Text, nullable=True)
    content = db.Column(db.String(500), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"""
        Post title:
        {self.title}

        {self.image} 

        {self.content}
        
        Posted at:
        {self.date_posted}
        """

db.create_all()



class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Please use a different username. Current username is already taken')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class PostForm(FlaskForm):
    title = StringField('title')
    image = FileField("Image", validators=[FileAllowed('jpg', 'png')], default="static/newpost.png")
    video_audio = FileField("Video-audio", validators=[FileAllowed('mp3', 'mp4')])
    content = TextAreaField('Content')
    submit = SubmitField('Post!')

class CommunityForm(FlaskForm):
    name = StringField('Community Name', validators=[DataRequired()])
    desc = TextAreaField("Community Description", validators=[DataRequired()])
    submit = SubmitField('Create')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField("Email")
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')


@app.route('/')
def home():
    current_users = User.query.all()
    return render_template('open.html', current_users=current_users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("user"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for('user'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations , you are now a registered user!')
        return redirect(url_for('login')) 
    return render_template('register.html', title='Register', form=form)



@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    user = current_user
    community = Community.query.all()
    user = User.query.filter_by(username=current_user.username).first()
   #posts = Post.query.all()
    return render_template("user.html", user=user, community=community)

@app.route('/community', methods=["GET", "POST"])
@login_required
def community():
    form = CommunityForm()
    if form.validate_on_submit():
        community = Community(name=form.name.data, desc=form.desc.data)
        db.session.add(community)
        db.session.commit()
        flash(f"Congratulation, community has been created!")
        return redirect(url_for('user'))
    return render_template("community.html", form=form)

@app.route('/comm', methods=["GET", "POST"])
@login_required
def fcommunity():
    return render_template("fcomm.html")

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('user'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
    
    
if __name__ == '__main__':
    app.run(debug=True)