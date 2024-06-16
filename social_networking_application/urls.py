from django.urls import path, include
from social_networking_application import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'friend-request', views.FriendRequestViewSet, basename='friend_request')

urlpatterns = [
    path('register', views.RegisterView.as_view(), name='register'),
    path('login', views.LoginView.as_view(), name='register'),

    path('users', views.UserListView.as_view(), name='user_list'),
    path('user/<int:pk>', views.UserDetailView.as_view(), name='user_detail'),

    path('filter-users', views.FilterUsers.as_view(), name='filter_users'),
    path('users-to-send-friend-request', views.UsersToSendFriendRequestView.as_view(), name='users_to_send_friend_request'), 

    path('', include(router.urls)),
    
    path('accepted-friends', views.FriendListView.as_view(), name='accepted_friends'),
    path('pending-friend-request', views.PendingFriendRequestListView.as_view(), name='pending_friend_requests'),
]
