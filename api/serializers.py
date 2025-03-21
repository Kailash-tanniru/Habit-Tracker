from datetime import date
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from api.models import CustomUser, Habit, HabitLog

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

    def update(self, instance, validated_data):
        instance.email = validated_data.get('email', instance.email)
        instance.username = validated_data.get('username', instance.username)
        
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)
        
        instance.save()
        return instance

from rest_framework import serializers



class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for handling password reset requests.
    Validates the email and ensures the user exists.
    """
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        """
        Validate that the email is associated with a user.
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user is associated with this email address.")
        return value


class PasswordResetOTPVerifySerializer(serializers.Serializer):
    """
    Serializer for verifying the OTP during password reset.
    Validates the email and OTP.
    """
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(max_length=6, required=True)

    def validate(self, data):
        """
        Validate the OTP and ensure it matches the user's OTP.
        """
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "User with this email does not exist."})

        if not user.is_reset_password_otp_valid(otp):
            raise serializers.ValidationError({"otp": "Invalid or expired OTP."})

        return data


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(max_length=6, required=True)
    new_password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    
    def validate(self, data):
        # Check if passwords match
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})

        # Check if the user exists
        try:
            user = CustomUser.objects.get(email=data["email"])
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError({"email": "User with this email does not exist."})

        # Check if the OTP is valid
        if not user.is_reset_password_otp_valid(data["otp"]):
            raise serializers.ValidationError({"otp": "Invalid or expired OTP."})

        # Add the user object to the validated data for use in the view
        data["user"] = user
        return data







# class HabitLogSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = HabitLog
#         fields = ['id', 'date', 'completed', 'notes', 'mood', 'journal_entry', 'created_at']

class HabitLogSerializer(serializers.ModelSerializer):
    mood = serializers.CharField(allow_blank=True, allow_null=True)

    notes = serializers.CharField(allow_blank=True, allow_null=True)

    class Meta:
        model = HabitLog
        fields = ['date', 'completed', 'notes', 'mood']

    def validate_mood(self, value):
        if value and value not in dict(Habit.MOOD_CHOICES).keys():
            raise serializers.ValidationError("Invalid mood choice.")
        return value

    def update(self, instance, validated_data):
        instance.completed = validated_data.get('completed', instance.completed)
        instance.notes = validated_data.get('notes', instance.notes)
        instance.mood = validated_data.get('mood', instance.mood)
        instance.save()
        return instance


# HABIT SERIALIZER
class HabitSerializer(serializers.ModelSerializer):
    print('hi')
    class Meta:
        model = Habit
        fields = [
           'id', 'name', 'description', 'start_date', 'end_date', 'reminder_toggle', 'reminder_type','frequency',
         'reward','is_important',
        ]

    def validate(self, data):
        reminder_toggle = data.get('reminder_toggle', False)
        reminder_type = data.get('reminder_type', 'none')

        if reminder_toggle and not reminder_type:
            raise serializers.ValidationError({"reminder_type": "Reminder type is required when reminder toggle is enabled."})

        if reminder_toggle and reminder_type not in dict(Habit.REMINDER_CHOICES).keys():
            raise serializers.ValidationError({"reminder_type": "Invalid reminder type."})

        return data
    def validate_reminder_time(self, value):
        if value and not isinstance(value, str):
            raise serializers.ValidationError("Invalid reminder time format.")
        return value

    def validate_frequency(self, value):
        if value not in dict(Habit.FREQUENCY_CHOICES).keys():
            raise serializers.ValidationError("Invalid frequency choice.")
        return value

#Serializer for the updatation of the description and end_date of the particular habit
class HabitUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Habit
        fields = ['description', 'end_date']

    def validate_description(self, value):
        if not value.strip():
            raise serializers.ValidationError("Description cannot be empty.")
        return value

    def validate_end_date(self, value):
        if value < self.instance.start_date:
            raise serializers.ValidationError("End date cannot be before the start date.")
        return value

# class HabitDetailSerializer(serializers.ModelSerializer):
#     remaining_days = serializers.SerializerMethodField()
#     is_completed_today = serializers.BooleanField(source='is_completed_today')
#     current_streak = serializers.IntegerField(source='current_streak')
#     max_streak = serializers.IntegerField(source='max_streak')
#     is_active = serializers.BooleanField(source='is_active')

#     class Meta:
#         model = Habit
#         fields = [
#             'id', 'name', 'description', 'start_date', 'end_date',
#             'remaining_days', 'current_streak', 'max_streak', 
#             'is_completed_today', 'is_active', 'frequency', 'reminder_time'
#         ]

#     def get_remaining_days(self, obj):
#         if obj.end_date:
#             return (obj.end_date - date.today()).days
#         return None
    
class HabitDetailSerializer(serializers.ModelSerializer):
    # remaining_days = serializers.SerializerMethodField()
    # is_completed_today = serializers.BooleanField(source='is_completed_today')
    # current_streak = serializers.IntegerField(source='current_streak')
    # max_streak = serializers.IntegerField(source='max_streak')
    # is_active = serializers.BooleanField()
    

    class Meta:
        model = Habit
        fields = [
            'id', 'name', 'description', 'start_date', 'end_date',
            'remaining_days', 'current_streak', 'max_streak', 
            'is_completed_today', 'is_active', 'frequency', 'reminder_time','reward','streak_updated_at','logs','is_achieved'
        ]

    def get_remaining_days(self, obj):
        if obj.end_date:
            return (obj.end_date - date.today()).days
        return None

    def validate_is_active(self, value):
        if not isinstance(value, bool):
            raise serializers.ValidationError("Invalid value for is_active.")
        return value
