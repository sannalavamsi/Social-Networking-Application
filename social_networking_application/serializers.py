import logging
from rest_framework import serializers
from .models import User, FriendRequest, Friendship

logger = logging.getLogger(__name__)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'name','password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password']
        )
        logger.info(f"{user.email} Registered Successfully")
        return user
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        logger.info(f"User {instance.email} updated successfully.")
        return instance

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password']

class FriendRequestSerializer(serializers.ModelSerializer):
    from_user = UserSerializer(read_only=True)
    to_user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    to_user_details = UserSerializer(source='to_user', read_only=True) 

    class Meta:
        model = FriendRequest
        fields = ['id', 'from_user', 'to_user','to_user_details','status' ,'created_at']

class FriendshipSerializer(serializers.ModelSerializer):
    user1 = UserSerializer(read_only=True)
    user2 = UserSerializer(read_only=True)
    class Meta:
        model = Friendship
        fields = ['id', 'user1', 'user2']