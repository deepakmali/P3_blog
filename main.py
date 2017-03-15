import os
import webapp2
import jinja2
import data_model
import re
import hmac

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
                               autoescape = True)


SECRET_KEY = "aghkZXZ#Tm9u5ZXZ1Bvc3RzG!CAgICAgMA"


# create hash to set in cookie
def create_cookie_hash(userid):
    return '%s|%s' %(userid, hmac.new(SECRET_KEY, userid).hexdigest())

def validate_cookie_hash(user_hash):
    userid = user_hash.split('|')[0]
    if user_hash == create_cookie_hash(userid = userid):
        return userid

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write((self.render_str(template, **kw)))

    def loggedUser(self, user_hash):
        userid = validate_cookie_hash(user_hash)
        # return userid
        if userid :
            return data_model.User.get_user_by_id(int(userid)).key().id()



class MainPage(Handler):
    def get(self):
        self.render("MainPage.html")

class BlogHome(Handler):
    def get(self):
        self.render("Home.html")

class NewPost(Handler):
    def get(self):
        self.render("NewPost.html")
    # Add code to save the post
        

class Signup(Handler):
    def get(self):
        user_hash = str(self.request.cookies.get('userid'))
        userid = self.loggedUser(user_hash = user_hash)
        self.write(userid)
        # self.render("signup.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        # self.write(username)
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        password_re = re.compile(r"^.{3,20}$")
        email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")

        if not username_re.match(username):
            username_error = "Username does not meet the specifications. Try another"
        if not password_re.match(password):
            password_error = "Password is very weak and not according to the policy."
        if password != verify :
            verify_error = "Re-entered password does not match the password."
        if (email and (not email_re.match(email))):
            email_error = "It's not a valid email. Enter valid email!!"

        if len(username_error + password_error + verify_error + email_error) > 0 :
            self.render("signup.html",
                        username = username,
                        email = email,
                        username_error = username_error,
                        password_error = password_error,
                        verify_error = verify_error,
                        email_error = email_error
                        )
        else:
            # check if username already exists
            user = data_model.User.get_by_name(username)
            if user :
                self.render("signup.html", user_exists_error= "Username: %s already"
                            " exists!! try with different user" % username)
            else:
                data_model.User.register(username = username,
                                         password = password,
                                         email = email)
            self.redirect('/blog/login')

class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if not username:
            self.render("login.html", empty_username = "Username can not be empty")
        elif not password:
            self.render("login.html", empty_password = "Password can not be empty")
        else:
            name = data_model.User.login(username = username,
                              password = password
                              )
            if name :
                # self.write('hello' + name.username )
                # Set cookie for the user.
                cookie_val = create_cookie_hash(str(name.key().id()))
                self.response.headers.add_header('Set-Cookie',
                                                '%s=%s' %('userid', cookie_val))
                self.write(cookie_val)
                self.redirect('/blog/mypage')

            else:
                self.render("login.html",
                            empty_password="Password is incorrect.")

class MyPage(Handler):
    pass



app = webapp2.WSGIApplication([
                              ( '/', MainPage),
                              ( '/blog', BlogHome),
                              ( '/blog/newpost', NewPost),
                              ( '/blog/signup', Signup),
                              ( '/blog/login', Login),
                              ( '/blog/mypage', MyPage),
                              ] , 
                              debug = True)