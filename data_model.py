import os
from string import letters
import random
import hashlib
from google.appengine.ext import db


# methods of hashing
def make_salt():
    return ''.join(random.choice(letters) for x in range(5))


def make_pw_hash(username, password, salt=None):
    if not salt:
        salt = make_salt()
    return '%s|%s' % (salt,
                      hashlib.sha256(username + password + salt).hexdigest())


def valid_password(username, password, password_hash):
    salt = password_hash.split('|')[0]
    return password_hash == make_pw_hash(username, password, salt)


# To store user details.
class User(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    # class method to search a user by username
    @classmethod
    def get_by_name(cls, user):
        return cls.all().filter('username = ', user).get()

    # class method to search user by id
    @classmethod
    def get_user_by_id(cls, userId):
        return cls.get_by_id(userId)

    # method to hash password and return user object
    @classmethod
    def register(cls, username, password, email=None):
        pw_hash = make_pw_hash(username=username, password=password)
        return cls(username=username,
                   password_hash=pw_hash,
                   email=email).put()

    # Method to return user object if login credentials are valid.
    @classmethod
    def login(cls, username, password):
        user = cls.get_by_name(user=username)
        if user and valid_password(username, password, user.password_hash):
            return user


# To store blog posts
class BlogPosts(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.ReferenceProperty(User)
    total_likes = db.IntegerProperty(default=0)
    total_comments = db.IntegerProperty(default=0)

    # method to return most recent 10 posts
    @classmethod
    def recent_ten(cls):
        return cls.all().order('-created').fetch(10)

    @classmethod
    def get_post(cls, postId):
        return cls.get_by_id(int(postId))

    @classmethod
    def user_posts(cls, user):
        return cls.all().filter('created_by =', user)

    # Incrementing the comment count
    def increment_comment_count(self):
        self.total_comments += 1
        self.put()

    # Incrementing the likes count
    def increment_like_count(self):
        self.total_likes += 1
        self.put()

    def decrement_like_count(self):
        self.total_comments -= 1
        self.put()


# To store comments on posts
class Comments(db.Model):
    post = db.ReferenceProperty(BlogPosts)
    user = db.ReferenceProperty(User)
    comment_text = db.TextProperty(required=True)

    @classmethod
    def get_post_comments(cls, post):
        if post:
            return cls.all().filter('post =', post)

    @classmethod
    def put_post_comments(cls, post, user, comment_text):
        if post and user and comment_text:
            obj = Comments(post=post,
                           user=user,
                           comment_text=comment_text)
            obj.put()
            post.increment_comment_count()

    @classmethod
    def get_comment(cls, commentId):
        return cls.get_by_id(int(commentId))

    @classmethod
    def get_postId(cls, commentId):
        comment = cls.get_comment(commentId)
        return comment.post.key().id()


# Store the likes on posts
class Likes(db.Model):
    post = db.ReferenceProperty(BlogPosts)
    user = db.ReferenceProperty(User)

    @classmethod
    def put_liked_user(cls, post, user):
        if post and user:
            cls(post=post, user=user).put()
            # obj.put()
            post.increment_like_count()
            # cls(post = post,
            #     user = user).put()

    @classmethod
    def check_if_liked(cls, post, user):
        return cls.all().filter('post =', post).filter('user =', user).count()
