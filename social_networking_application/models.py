from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True)
    name=models.CharField(max_length=256)
    password = models.CharField(max_length=256)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name','password']

    def __str__(self):
        return self.email
    
class FriendRequest(models.Model):
    from_user = models.ForeignKey(User, related_name='sent_friend_requests', on_delete=models.CASCADE)
    to_user = models.ForeignKey(User, related_name='received_friend_requests', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=(
        ('pending', 'Pending'),
        ('accepted', 'Accepted')
    ), default='pending')

    class Meta:
        unique_together = ('from_user', 'to_user')

    def __str__(self):
        return f"{self.from_user} to {self.to_user} - {self.status}"

class Friendship(models.Model):
    user1 = models.ForeignKey(User, related_name='friendships1', on_delete=models.CASCADE)
    user2 = models.ForeignKey(User, related_name='friendships2', on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user1', 'user2')

    def __str__(self):
        return f"{self.user1} & {self.user2}"