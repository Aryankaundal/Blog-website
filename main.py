from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, inspect
from sqlalchemy.pool import NullPool
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ContactForm
import smtplib
from email.mime.text import MIMEText
import os
from threading import Thread

# ---------- App init ----------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY', 'dev-secret')

ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# ---------- Database config ----------
class Base(DeclarativeBase):
    pass

# DB URI: prefer env var DB_URI (set to your Supabase URI in Vercel).
# Fallback to SQLite for local dev.
db_uri = os.environ.get("DB_URI", "sqlite:///posts.db")
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

# Engine options: use NullPool (serverless friendly). For Postgres ensure sslmode=require.
engine_options = {"poolclass": NullPool}
# If the URI contains 'postgres' ensure sslmode (SQLAlchemy connect_args only used for some drivers)
if "postgres" in (db_uri or "").lower() or "postgresql" in (db_uri or "").lower():
    engine_options["connect_args"] = {"sslmode": "require"}

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# ---------- Models ----------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(200))
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


# ---------- Extras ----------
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# ---------- Safe table creation ----------
def ensure_tables():
    """
    Create missing tables safely. Called from before_first_request or admin endpoint.
    Not called at import time to avoid cold-start crashes on serverless platforms.
    """
    try:
        inspector = inspect(db.engine)
        # check for one known table to decide if we need to create_all
        if not inspector.has_table("users"):
            db.create_all()
            app.logger.info("Created missing tables.")
    except Exception as e:
        # Log, but don't crash the import or request
        app.logger.exception("ensure_tables failed: %s", e)


# run ensure_tables exactly once per process, on the first request handled by this process.
tables_checked = False

@app.before_request
def ensure_tables_once():
    # `tables_checked` is per-process; serverless may spin up many processes — that's fine.
    global tables_checked
    if tables_checked:
        return
    try:
        ensure_tables()
        tables_checked = True
        app.logger.info("ensure_tables executed successfully")
    except Exception as e:
        # log, but don’t crash the import or the request handling
        app.logger.exception("ensure_tables failed: %s", e)
        # don't set tables_checked so future requests can retry



# Admin route to create tables manually (protect in prod)
@app.route('/admin/create-tables', methods=['POST'])
def admin_create_tables():
    # implement auth for this route in production
    try:
        ensure_tables()
        return "tables ensured", 200
    except Exception:
        app.logger.exception("admin create-tables failed")
        return "error", 500


# ---------- Login loader ----------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


# ---------- Decorators ----------
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


def only_commenter(function):
    """
    Verifies the current user is the author of the comment being acted upon.
    Works for routes that receive comment_id as a keyword arg or positional arg.
    """
    @wraps(function)
    def check(*args, **kwargs):
        if not current_user.is_authenticated:
            return abort(403)

        comment_id = kwargs.get("comment_id", None)
        # try positional (e.g. delete_comment(post_id, comment_id))
        if comment_id is None and len(args) >= 2:
            # expecting second positional arg to be comment_id in that route signature
            comment_id = args[1]

        if comment_id is None:
            return abort(403)

        try:
            comment = db.session.get(Comment, int(comment_id))
        except Exception:
            return abort(403)

        if not comment or comment.author_id != current_user.id:
            return abort(403)

        return function(*args, **kwargs)
    return check


# ---------- Routes (your original logic, unchanged) ----------
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
    per_page = 5
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
def delete_comment(post_id, comment_id):
    post_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(post_to_delete)
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

        thread = Thread(
            target=send_email_async,
            args=(app, msg, sender_email, sender_password)
        )
        thread.start()

        flash("Message sent successfully!", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html", form=form)


if __name__ == "__main__":
    # local development: create tables right away for convenience
    with app.app_context():
        ensure_tables()
    app.run(debug=False)
