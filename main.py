import ast, urllib
from flask import Flask, request, abort, session, redirect, url_for, render_template, flash, g
from flask.globals import _app_ctx_stack, _request_ctx_stack
from werkzeug.urls import url_parse
from werkzeug.routing import BuildError
from wtforms import Form, StringField, PasswordField, validators
from wtforms.csrf.session import SessionCSRF
from datetime import timedelta
from passlib.context import CryptContext
from functools import wraps

no_redir = [None, 'login', 'register']

app = Flask(__name__)
app.secret_key = 'changeme'

pwd_context = CryptContext(
    schemes=["pbkdf2_sha512"],
    deprecated="auto",
)

from pony.orm import *

sql_debug(True)
db = Database()
db.bind('sqlite', 'data.sqlite', create_db=True)


class Account(db.Entity):
    name = Required(str)
    username = Required(str)
    password = Required(str)


db.generate_mapping(create_tables=True)


class SecureForm(Form):
    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = 'changeme'
        csrf_time_limit = timedelta(minutes=20)


class LoginForm(SecureForm):
    username = StringField('Username', [validators.required(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.required()])


class RegisterForm(SecureForm):
    name = StringField('Real Name', [validators.required()])
    username = StringField('Username', [validators.required()])
    password = PasswordField('Password', [validators.required(),
                                          validators.Length(min=6),
                                          validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')


@app.template_filter('route_from')
def route_from(url, method=None):
    appctx = _app_ctx_stack.top
    reqctx = _request_ctx_stack.top
    if appctx is None:
        raise RuntimeError('Attempted to match a URL without the '
                           'application context being pushed. This has to be '
                           'executed when application context is available.')

    if reqctx is not None:
        url_adapter = reqctx.url_adapter
    else:
        url_adapter = appctx.url_adapter
        if url_adapter is None:
            raise RuntimeError('Application was not able to create a URL '
                               'adapter for request independent URL matching. '
                               'You might be able to fix this by setting '
                               'the SERVER_NAME config variable.')
    parsed_url = url_parse(url)
    if parsed_url.netloc is not "" and parsed_url.netloc != url_adapter.server_name:
        raise abort(401, "You are not authorized to perform this action.  (PARSED_URL MISMATCH")
    return ast.literal_eval(str(url_adapter.match(parsed_url.path, method)))[0]  # there has to be a better way to do this


@app.before_request
@db_session
def get_user():
    if session.has_key('userid'):
        g.user = Account.get(id=session['userid'])


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.has_key('userid'):
            try:
                next = route_from(request.path)
                return redirect(url_for("login") + "?" + urllib.urlencode({'next': next}))
            except Exception, e:
                return abort(404, "Could not build url for endpoint.")
        return f(*args, **kwargs)

    return decorated


@app.route("/ah/Login", methods=['GET', 'POST'])
@db_session
def login():
    next = request.args.get('next') if (request.args.get('next') not in no_redir) else 'index'
    try:
        next_url = url_for(next)
    except BuildError:
        return abort(404, "Could not build url for endpoint.")
    form = LoginForm(request.form, meta={'csrf_context': session})
    if request.method == "POST" and form.validate():
        c = Account.get(username=form.username.data)
        if not c:
            flash("Incorrect username or password.")
            return render_template("login.html", form=form, next=next)
        if not pwd_context.verify(form.password.data, c.password):
            flash("Incorrect username or password.")
            return render_template("login.html", form=form, next=next)
        session['userid'] = c.id
        return redirect(next_url)
    else:
        return render_template("login.html", form=form, next=next)


@app.route("/ah/Logout")
def logout():
    next = request.args.get('next') if (request.args.get('next') not in no_redir) else 'index'
    try:
        next_url = url_for(next)
    except BuildError:
        return abort(404, "Could not build url for endpoint.")
    session.pop('userid', None)
    flash("You have been logged out.")
    return redirect(next_url)


@app.route("/ah/Register", methods=['GET', 'POST'])
@db_session
def register():
    next = request.args.get('next') if (request.args.get('next') not in no_redir) else 'index'
    try:
        next_url = url_for(next)
    except BuildError:
        return abort(404, "Could not build url for endpoint.")
    form = RegisterForm(request.form, meta={'csrf_context': session})
    if request.method == "POST" and form.validate():
        hash = pwd_context.encrypt(form.password.data)
        c = Account(name=form.name.data, username=form.username.data.lower(), password=hash)
        commit()
        session['userid'] = c.id
        flash("You have successfully registered.")
        return redirect(next_url)
    else:
        return render_template("register.html", form=form)


@app.route("/")
@requires_auth
@db_session
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
