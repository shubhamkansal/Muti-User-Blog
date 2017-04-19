import os
import re
import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import db
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'hashsecret'

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hashdigest())

def check_secure_val(str1):
    val = str1.split('|')[0]
    if str1 == make_secure_val(val):
        return val

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
    	value = make_secure_val(val)
    	self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
    		                              % (name, value))

    def read_secure_cookie(self, name):
    	value = self.request.cookies.get(name)
    	return value and check_secure_val(value)

    def login(self, user):
    	self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
    	self.response.headers.add_header('Set-Cookie',
    		                             'user_id=; Path=/')

    def initialize(self, *a, **kw):
    	webapp2.RequestHandler.initialize(self, *a, **kw)
    	userid = self.read_secure_cookie('user_id')
    	self.user = userid and User.by_id(int(uid))

def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):

        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Likes(db.Model):
    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_author(cls, author_id):
        key = db.GqlQuery('select * from Likes where post = :1',
                          author_id)
        return key.count()

    @classmethod
    def check_likes(cls, author_id, user_id):
        key = Likes.all().filter('post =', author_id).filter('user =', user_id)
        return key.count()

    def render(self):
        return render_str('post.html', p=self)


class unLikes(db.Model):
    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_author(cls, author_id):
        key = db.GqlQuery('select * from unLikes where post = :1',
                          author_id)
        return key.count()

    @classmethod
    def check_unlikes(cls, author_id, user_id):
        key = unLikes.all().filter('post =', author_id).filter('user =',
                                                               user_id)
        return key.count()

    def render(self):
        return render_str('post.html', p=self)


class Comments(db.Model):
    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty()

    @classmethod
    def by_author(cls, author_id):
        key = \
            db.GqlQuery('select * from Comments where post = :1 order by created desc',  # NOQA
                        author_id)
        return key

    @classmethod
    def by_id(cls, uid):
        return Comments.get_by_id(uid, parent=users_key())

    def render(self):
        return render_str('comment.html', c=self)


class FrontPage(BlogHandler):
    def get(self):
        posts = \
            db.GqlQuery('select * from Post order by created desc limit 10'
                        )
        self.render('front.html', posts=posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        prev_comments = Comments.by_author(post)
        error = ''
        if not post:
            self.render('notfound.html')
            return

        likes = Likes.by_author(post)
        unlikes = unLikes.by_author(post)
        if self.read_secure_cookie('user_id') == "":
            self.redirect('/login')
        self.render(
            'permalink.html',
            post=post,
            likes=likes,
            unlikes=unlikes,
            prev_comments=prev_comments,
            error=error,
            )

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likes = Likes.by_author(post)
        prev_comments = Comments.by_author(post)
        unlikes = unLikes.by_author(post)
        
        if self.user:
            user_id = User.by_name(self.user.name)
            prev_liked = Likes.check_likes(post, user_id)
            prev_unliked = unLikes.check_unlikes(post, user_id)

            if self.request.get('like'):
                if post.author_id \
                        != str(self.user.key().id()):
                    if prev_liked == 0:
                        l = Likes(post=post,
                                  user=User.by_name(self.user.name))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/blog/post/%s'
                                      % str(post.key().id()))
                    else:
                        error = 'You Have already Liked this Post'
                        self.render(
                            'permalink.html',
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            prev_comments=prev_comments,
                            error=error,
                            )
                else:

                    error = 'You cannot like your own post'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            if self.request.get('unlike'):
                if post.author_id \
                   != str(self.user.key().id()):
                    if prev_unliked == 0:
                        ul = unLikes(post=post,
                                     user=User.by_name(self.user.name))
                        ul.put()
                        time.sleep(0.1)
                        self.redirect('/blog/post/%s'
                                      % str(post.key().id()))
                    else:
                        error = 'You have already Unliked this Post'
                        self.render(
                            'permalink.html',
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            prev_comments=prev_comments,
                            error=error,
                            )
                else:
                    error = 'You cannot unlike your own post'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            if self.request.get('edit'):
                if post.author_id \
                   == str(self.user.key().id()):
                    self.redirect('/editpost/%s' % str(post.key().id()))
                else:
                    error = 'Cannot edit other people posts'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )
            if self.request.get('delete'):
                if post.author_id \
                   == str(self.user.key().id()):
                    self.redirect('/deletepost/%s'
                                  % str(post.key().id()))
                else:
                    error = 'Cannot delete other people posts'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )
            if self.request.get('comment'):
                comment_content = self.request.get('comment')
                if comment_content:
                    c = Comments(post=post,
                                 user=User.by_name(self.user.name),
                                 comment=comment_content,
                                 author=str(self.user.key().id()))
                    c.put()
                    time.sleep(0.2)
                    self.redirect('/blog/post/%s'
                                  % str(post.key().id()))
                else:
                    error = 'Enter a comment in the area'
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )

            if self.request.get('edit_comment'):
                c = Comments.by_author(post).get()
                if str(c.author) == str(self.user.key().id()):
                    self.redirect('/editcomment/%s' % str(c.key().id()))
                else:
                    error = "You cannot edit some other user's comment"
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )
            if self.request.get('delete_comment'):
                c = Comments.by_author(post).get()
                if str(c.author) == str(self.user.key().id()):
                    time.sleep(0.1)
                    self.redirect('/deletecomment/%s'
                                  % str(c.key().id()))
                else:
                    error = \
                        "You cannot delete some other user's comment"
                    self.render(
                        'permalink.html',
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        prev_comments=prev_comments,
                        error=error,
                        )
        else:
            self.redirect('/login')

class NewPost(BlogHandler):
    def get(self):
        self.render('newpost.html')
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.user:
            if subject and content:
                p = Post(parent=blog_key(), subject=subject,
                         content=content,
                         author_id=str(self.user.key().id()))
                p.put()
                self.redirect('/blog/post/%s' % str(p.key().id()))
            else:
                error = 'subject and content, please!'
                self.render('newpost.html', subject=subject,
                            content=content, error=error)
        else:
            self.redirect('/login')


class EditPost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = post.subject
        content = post.content
        self.render('edit.html', subject=subject, content=content)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = Post.get_by_id(int(post_id), parent=blog_key())

        if self.request.get('cancel'):
                return self.redirect('/blog/post/%s' % str(p.key().id()))

        if self.user and p and p.author_id == str(self.user.key().id()):
                subject = self.request.get('subject')
                content = self.request.get('content')
                if subject and content:
                    p.subject = subject
                    p.content = content
                    p.put()
                    self.redirect('/blog/post/%s' % str(p.key().id()))
                else:
                    error = 'subject and content, please!'
                    self.render('edit.html', subject=subject, content=content,
                                error=error)
        else:
            self.redirect('/login')
        
        

class EditComment(BlogHandler):
    def get(self, post_id):
        p = Comments.get_by_id(int(post_id))
        content = p.comment
        self.render('editComment.html', subject=content)

    def post(self, comment_id):
        c = Comments.get_by_id(int(comment_id))
        if self.user and c and c.author == str(self.user.key().id()):
            content = self.request.get('comment_content')
            if content:
                c.comment = content
                c.put()
                self.redirect('/blog/')
            else:
                error = 'Add Comment, please!'
                self.render('editComment.html', error=error)
        else:
            self.redirect('/login')
        

class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = Post.get_by_id(int(post_id), parent=blog_key())

        if self.user and p and p.author_id == str(self.user.key().id()):
                p.delete()
                self.redirect('/blog')
        else:
            self.redirect('/login')
        

class DeleteComment(BlogHandler):
    def get(self, comment_id):
        c = Comments.get_by_id(int(comment_id))
        if self.user and c and c.author == str(self.user.key().id()):
            c.delete()
            self.redirect('/blog')
        else:
            self.redirect('/login')
   
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render('signup-form.html')

    def post(self):
        error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = 'This is not a valid username'
            error = True

        if not valid_password(self.password):
            params['error_password'] = 'This is not a valid password'
            error = True
        elif self.password != self.verify:
            params['error_verify'] = "Password didn't match"
            error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            error = True

        if error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'User already exists'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class MainHandler(BlogHandler):
    def get(self):
        self.redirect('/blog')

app = webapp2.WSGIApplication([    
	('/', MainHandler),
    ('/blog/?', FrontPage),
    ('/blog/post/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/editpost/([0-9]+)', EditPost),
    ('/deletepost/([0-9]+)', DeletePost),
    ('/editcomment/([0-9]+)', EditComment),
    ('/deletecomment/([0-9]+)', DeleteComment),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ], debug = True)
