import os
import webapp2
import jinja2
import data_model
import re
import hmac
import time


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET_KEY = "aghkZXZ#Tm9u5ZXZ1Bvc3RzG!CAgICAgMA"


# create hash to set in cookie
def create_cookie_hash(userid):
    return '%s|%s' % (userid, hmac.new(SECRET_KEY, userid).hexdigest())


def validate_cookie_hash(user_hash):
    userid = user_hash.split('|')[0]
    if user_hash == create_cookie_hash(userid=userid):
        return userid


# Helper method to render the page
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write((self.render_str(template, **kw)))

    # To check if an user is logged in.
    def loggedUser(self):
        user_hash = str(self.request.cookies.get('userid'))
        userid = validate_cookie_hash(user_hash)
        # return userid
        if userid:
            return data_model.User.get_user_by_id(int(userid)).key().id()


class MainPage(Handler):
    def get(self):
        self.render("MainPage.html")


# Display 10 most recent posts.
class BlogHome(Handler):
    def get(self):
        userid = self.loggedUser()
        if not userid:
            self.redirect("/blog/signup")
        else:
            posts=data_model.BlogPosts.recent_ten()
            if len(posts) > 0:
                self.render("Home.html",
                            posts=posts
                            )
            else:
                self.render("Home.html",
                            empty=True)

# Create new post
class NewPost(Handler):
    def get(self):
        userid = self.loggedUser()
        if not userid:
            self.redirect("/blog/signup")
        else:
            self.render("NewPost.html")

    # Add code to save the post
    def post(self):
        userid = self.loggedUser()
        if not userid:
            self.redirect("/blog/signup")
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            subject_error = ''
            content_error = ''
            if not subject:
                subject_error = "Subject can not be empty!!!"
            if not content:
                content_error = "Content can not be empty!!!"
            if subject and content:
                new_entry = data_model.BlogPosts(subject=subject,
                                                 content=content,
                        created_by=data_model.User.get_user_by_id(int(userid)))  # NOQA
                key = new_entry.put()
                self.redirect("/blog")
            else:
                self.render("NewPost.html",
                            subject=subject,
                            content=content,
                            subject_error=subject_error,
                            content_error=content_error)


# Handling signup process.
class Signup(Handler):
    def get(self):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            self.redirect('/blog/mypage')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        password_re = re.compile(r"^.{3,20}$")
        email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if not username_re.match(username):
            username_error = "Username does not meet the specifications.Try another"  # NOQA
        if not password_re.match(password):
            password_error = "Password is very weak and not according to the policy."  # NOQA
        if password != verify:
            verify_error = "Re-entered password does not match the password."
        if (email and (not email_re.match(email))):
            email_error = "It's not a valid email. Enter valid email!!"
        if len(username_error + password_error + verify_error + email_error) > 0:  # NOQA
            self.render("signup.html",
                        username=username,
                        email=email,
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error
                        )
        else:
            # check if username already exists
            user = data_model.User.get_by_name(username)
            if user:
                self.render("signup.html",
                            user_exists_error="Username: %s already"
                            " exists!! try with different user" % username)
            else:
                data_model.User.register(username=username,
                                         password=password,
                                         email=email)
            self.redirect('/blog/login')


# Handle login process
class Login(Handler):
    def get(self):
        userid = self.loggedUser()
        if not userid:
            self.render("login.html")
        else:
            self.redirect('/blog/mypage')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if not username:
            self.render("login.html",
                        empty_username="Username can not be empty")
        elif not password:
            self.render("login.html",
                        empty_password="Password can not be empty")
        else:
            name = data_model.User.login(username=username,
                                         password=password
                                         )
            if name:
                # self.write('hello' + name.username )
                # Set cookie for the user.
                cookie_val = create_cookie_hash(str(name.key().id()))
                self.response.headers.add_header('Set-Cookie',
                                                 '%s=%s; Path=/' %
                                                 ('userid', cookie_val))
                self.write(cookie_val)
                self.redirect('/blog/mypage')

            else:
                self.render("login.html",
                            empty_password="Password is incorrect.")


# Disply user's blogs
class MyPage(Handler):
    def get(self):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            user = data_model.User.get_user_by_id(int(userid))
            posts = data_model.BlogPosts.user_posts(user=user)
            posts_count = posts.count()
            if posts_count > 0:
                self.render("mypage.html",
                            posts=posts
                            )
            else:
                self.render("mypage.html",
                            empty=True
                            )


# Option to udpate existing post
class EditPost(Handler):
    def get(self, postId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            post = data_model.BlogPosts.get_post(postId=int(postId))
            self.render("NewPost.html",
                        subject=post.subject,
                        content=post.content
                        )

    def post(self, postId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            post = data_model.BlogPosts.get_post(postId=int(postId))
            if int(post.created_by.key().id()) == int(userid):
                post.subject = self.request.get('subject')
                post.content = self.request.get('content')
                post.put()
                self.redirect('/blog/mypage')
            else:
                self.render("NewPost.html",
                            not_owner="""Editing is not allowed on 
                            other user's posts"""
                            )


# Logging out user and un-setting the cookie.
class Logout(Handler):
    def get(self):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            self.response.headers.add_header('Set-Cookie', 'userid=; Path=/')
            self.render("logout.html")


class Comment(Handler):
    def get(self, postId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            post = data_model.BlogPosts.get_post(postId=postId)
            user = data_model.User.get_user_by_id(int(postId))
            comments = data_model.Comments.get_post_comments(post=post)
            loggedUser = data_model.User.get_user_by_id(int(userid))
            self.render("comments.html",
                        post=post,
                        comments=comments,
                        loggedUser=loggedUser
                        )

    def post(self, postId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            post = data_model.BlogPosts.get_post(postId=postId)
            user = data_model.User.get_user_by_id(int(userid))
            comment_text = self.request.get('comment')
            data_model.Comments.put_post_comments(post=post,
                                                  user=user,
                                                  comment_text=comment_text
                                                  )
            self.redirect("/blog")


class Like(Handler):
    def get(self, postId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            post = data_model.BlogPosts.get_post(postId=postId)
            # user = post.created_by
            user = data_model.User.get_user_by_id(int(userid))
            if user.username == post.created_by.username:
                like_response = """Sorry! Owner of the post is not allowed to
                                like his own post!! <br>
                                We are glad that you like your post though ;)
                                """
            elif data_model.Likes.check_if_liked(post=post, user=user) > 0:
                like_response = """
                        We know this post is <i>liking-multiple-times</i> good
                        <br> But sorry!! We don't allow multiple likes :(
                        """
            else:
                data_model.Likes.put_liked_user(post=post, user=user)
                like_response = """Thank you for liking the post :)"""
            self.render("likes.html",
                        like_response=like_response)


class DeletePost(Handler):
    def get(self, postId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            post = data_model.BlogPosts.get_post(int(postId))
            if int(post.created_by.key().id()) == int(userid):
                post.delete()
                self.redirect("/blog/mypage")
            else:
                self.redirect("/blog/mypage")

class DeleteComment(Handler):
    def get(self, commentId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            comment = data_model.Comments.get_comment(int(commentId))
            if comment:
                postId = data_model.Comments.get_postId(int(commentId))
            else:
                self.redirect("/blog/mypage")
            if comment and postId:
                if int(comment.user.key().id()) == int(userid):
                    comment.delete()
                    post = data_model.BlogPosts.get_post(int(postId))
                    post.decrement_like_count()
                    self.redirect("/blog/comment-" + str(postId))
                else:
                    self.redirect("/blog/mypage")
            else:
                self.redirect("/blog/mypage")


class EditComment(Handler):
    def get(self, commentId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            comment = data_model.Comments.get_comment(int(commentId))
            self.render("commentEdit.html",
                        comment_text=comment.comment_text)

    def post(self, commentId):
        userid = self.loggedUser()
        if not userid:
            self.render("signup.html")
        else:
            comment = data_model.Comments.get_comment(int(commentId))
            if comment and (int(comment.user.key().id()) == int(userid)):
                comment_text = self.request.get('comment_text')
                comment.comment_text = comment_text
                comment.put()
                postId = data_model.Comments.get_postId(int(commentId))
                self.redirect("/blog/comment-" + str(postId))
            else:
                self.redirect("/blog/mypage")


app = webapp2.WSGIApplication([
                              ('/', MainPage),
                              ('/blog', BlogHome),
                              ('/blog/newpost', NewPost),
                              ('/blog/signup', Signup),
                              ('/blog/login', Login),
                              ('/blog/mypage', MyPage),
                              (r'/blog/mypage/(\d+)', EditPost),
                              (r'/blog/mypage/del-(\d+)', DeletePost),
                              ('/blog/logout', Logout),
                              (r'/blog/comment-(\d+)', Comment),
                              (r'/blog/mypage/delcomm-(\d+)', DeleteComment),
                              (r'/blog/mypage/edit-(\d+)', EditComment),
                              (r'/blog/like-(\d+)', Like),
                              ],
                              debug=True)
