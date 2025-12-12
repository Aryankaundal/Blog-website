# main.py
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ContactForm
import smtplib
from email.mime.text import MIMEText
import os
from threading import Thread

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')

# Bootstrap + CKEditor
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# DB URI fallback to sqlite if not provided
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
# Optional: avoid track modifications warnings
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# --------------------------
# Models
# --------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)

# Gravatar
gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

# --------------------------
# Lazy table creation — safe for serverless / Vercel import
# --------------------------
_tables_created = False

@app.before_request
def ensure_tables_once():
    """
    Create DB tables once per process on the first request served by that process.
    This avoids `db.create_all()` during import time which can crash imports when DB URI is not valid.
    """
    global _tables_created
    if _tables_created:
        return

    try:
        # create_all() is idempotent; safe to call multiple times.
        db.create_all()
        _tables_created = True
        app.logger.info("Database tables ensured (db.create_all executed).")
    except Exception as e:
        # Log the exception but don't crash the import. Next request will retry.
        app.logger.exception("db.create_all() failed: %s", e)
        # Keep _tables_created as False so we retry later.

# --------------------------
# Flask-Login loader
# --------------------------
@login_manager.user_loader
def load_user(user_id):
    # user_id is usually a string — convert to int and fetch with session.get
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# --------------------------
# Decorators
# --------------------------
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Ensure authentication first
        if not current_user.is_authenticated or getattr(current_user, "id", None) != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        # Only authenticated users can delete their own comments
        if not current_user.is_authenticated:
            return abort(403)

        # find comment by id (passed in kwargs or args)
        # We expect the route to pass comment_id as argument — function signature should match
        comment_id = kwargs.get("comment_id")
        if comment_id is None and len(args) > 0:
            # fallback: if decorator applied to route with (post_id, comment_id) signature
            # try to infer comment_id as last arg
            comment_id = args[-1]

        try:
            comment = db.session.get(Comment, int(comment_id))
        except Exception:
            comment = None

        if comment is None or comment.author_id != current_user.id:
            return abort(403)

        return function(*args, **kwargs)
    return check

# --------------------------
# Routes: Auth / Posts / Comments / Contact
# --------------------------
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/")
def get_all_posts():
    page = request.args.get("page", 1, type=int)
    per_page = 5   # number of posts per page

    posts = BlogPost.query.order_by(BlogPost.id.desc()).paginate(
        page=page,
        per_page=per_page
    )

    return render_template("index.html", posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete/comment/<int:comment_id>/<int:post_id>")
@only_commenter
def delete_comment(comment_id, post_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


def send_email_async(app, msg, sender_email, sender_password):
    with app.app_context():
        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(sender_email, sender_password)
                smtp.send_message(msg)
        except Exception as e:
            app.logger.exception("Email Error: %s", e)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()

    if form.validate_on_submit():
        sender_email = os.environ.get("MY_EMAIL")
        sender_password = os.environ.get("MY_PASS")
        receiver_email = os.environ.get("MY_EMAIL")

        body = f"""
New Contact Form Submission:

Name: {form.name.data}
Email: {form.email.data}

Message:
{form.message.data}
"""

        msg = MIMEText(body)
        msg["Subject"] = "New Contact Form Message"
        msg["From"] = sender_email
        msg["To"] = receiver_email

        # Run email sending in a background thread
        thread = Thread(
            target=send_email_async,
            args=(app, msg, sender_email, sender_password)
        )
        thread.start()

        flash("Message sent successfully!", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html", form=form)


# Run only when invoked directly (won't run on import)
if __name__ == "__main__":
    # debug=False in production; set True for local dev
    app.run(debug=False)
