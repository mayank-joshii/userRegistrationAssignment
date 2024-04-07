from rest_framework import serializers
from userapp.models import User

class userserializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only = True)

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    class Meta:
            model = User
            fields = ('username', 'email', 'password')

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


from rest_framework import serializers

class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()