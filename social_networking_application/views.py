import logging
from django.db.models import Q
from django.http import Http404
from rest_framework.decorators import action
from .models import User, FriendRequest, Friendship
from rest_framework import generics,status, viewsets
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework.exceptions import Throttled
from django.core.exceptions import ValidationError
from .responses import SuccessResponse,ErrorResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle
from rest_framework.pagination import PageNumberPagination
from .serializers import UserSerializer, LoginSerializer, FriendRequestSerializer, FriendshipSerializer

logger = logging.getLogger(__name__)

class UserPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

class FriendRequestThrottle(UserRateThrottle):
    scope = 'friend_request'
    rate = '3/minute'

class RegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data = request.data)
            serializer.is_valid(raise_exception = True)
            serializer.save()
            logger.info(f"User registered in successfully.")
            result= SuccessResponse(code=status.HTTP_201_CREATED,status='CREATED',message= "User Registered successfully.")
            return result.http_response(status=201) 
        except Exception as e:
            logger.error(f"Error while registering user: {e}")
            result= ErrorResponse(code=status.HTTP_400_BAD_REQUEST,status='BAD_REQUEST',message='Error while registering user.',errors=f'{e}')
            return result.http_response(status=400)

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            if email is None or password is None:
                logger.error("Email or password is missing in the request data.")
                result= ErrorResponse(
                    code=status.HTTP_400_BAD_REQUEST,
                    status='BAD_REQUEST',
                    message='Try again.',
                    errors='Email or password is missing.'
                    )
                return result.http_response(status=400)
            
            user = authenticate(email=email, password=password)

            if user is not None:
                logger.info(f"User {email} logged in successfully.")
                result= SuccessResponse(code=status.HTTP_200_OK,status='OK',message= f"User {email} logged in successfully.")
                return result.http_response(status=200) 
            else:
                logger.error(f"Failed login attempt for email: {email}. Invalid credentials.")
                result= ErrorResponse(code=status.HTTP_400_BAD_REQUEST,status='BAD_REQUEST',message=f"Failed login attempt for email: {email}. Invalid credentials.",errors='Invalid credentials.')
                return result.http_response(status=400) 
            
        except Exception as e:
            logger.error(f"Error: {e}")
            result= ErrorResponse(code=status.HTTP_500_INTERNAL_SERVER_ERROR,status='INTERNAL_SERVER_ERROR',message="Something went wrong",errors=f'{e}')
            return result.http_response(status=500)  
             
class FilterUsers(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    pagination_class = UserPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        query = self.request.query_params.get('q', '')
        if query is None:
            raise ValidationError({"filter_data": "This field is required."})
        queryset = User.objects.filter(Q(email__iexact=query) | Q(name__icontains=query))
        return queryset
    
    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            if not queryset.exists():
                logger.error("No Data Found.")
                result = ErrorResponse(
                    code=status.HTTP_404_NOT_FOUND,
                    status='NOT_FOUND',
                    message='No users found.',
                    errors='No users match the given filter.'
                )
                return result.http_response(status=status.HTTP_404_NOT_FOUND)
            
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            if page is None:
                logger.error("Invalid page requested.")
                result = ErrorResponse(
                    code=status.HTTP_400_BAD_REQUEST,
                    status='BAD_REQUEST',
                    message='Invalid page.',
                    errors='The requested page does not exist.'
                )
                return result.http_response(status=status.HTTP_400_BAD_REQUEST)
            
            serialized_data = self.serializer_class(page, many=True).data  
            next_page_url = paginator.get_next_link()
            prev_page_url = paginator.get_previous_link()

            logger.info("Users fetched successfully.")
            result = SuccessResponse(
                    code=200,
                    status='FETCHED',
                    message='Users fetched successfully.',
                    data=serialized_data,
                    next_page=next_page_url,
                    previous_page=prev_page_url
                )
            return result.http_response(status=status.HTTP_200_OK)
        
        except Http404:
            logger.error("No users found for the given query.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='No users found.',
                errors='No users found for the given query.'
            )
            return result.http_response(status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            logger.error(f"Error fetching user list: {e}")
            result = ErrorResponse(
                code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                status='INTERNAL_SERVER_ERROR',
                message='An error occurred while fetching the user list.',
                errors=str(e)
            )
            return result.http_response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FriendRequestViewSet(viewsets.ModelViewSet):
    serializer_class = FriendRequestSerializer
    permission_classes = [IsAuthenticated]
    throttle_classes = [FriendRequestThrottle]

    def get_queryset(self):
        return FriendRequest.objects.filter(to_user=self.request.user)

    def perform_create(self, serializer):
        try:
            from_user = self.request.user
            to_user = serializer.validated_data['to_user']

            if from_user == to_user:
                return Response({'error': 'Cannot send friend request to yourself.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if FriendRequest.objects.filter(from_user=from_user, to_user=to_user, status='pending').exists():
                return Response({'error': 'Friend request already sent.'}, status=status.HTTP_400_BAD_REQUEST)

            serializer.save(from_user=from_user)    

            logger.info(f"Friend request sent successfully from {self.request.user}.")
            result = SuccessResponse(
                code=201,
                status='CREATED',
                message='Friend request sent successfully.',
                data = serializer.data
            )
            return result.http_response(status=status.HTTP_201_CREATED)

        except ValueError as ve:
            logger.error(f"Error sending friend request: {ve}")
            result = ErrorResponse(
                code=status.HTTP_400_BAD_REQUEST,
                status='BAD_REQUEST',
                message='Error sending friend request.',
                errors=f'Error sending friend request: {ve}'
            )
            return result.http_response(status=400)

        except Throttled as e:
            logger.warning(f"User {self.request.user} has exceeded the rate limit for sending friend requests.")
            result = ErrorResponse(
                code=status.HTTP_429_TOO_MANY_REQUESTS,
                status='TOO_MANY_REQUESTS',
                message='Rate limit exceeded. Please try again later.',
                errors='Rate limit exceeded. Please try again later.'
            )
            return result.http_response(status=429)

        except Exception as e:
            logger.error(f"Error sending friend request: {e}")
            result = ErrorResponse(
                code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                status='INTERNAL_SERVER_ERROR',
                message='Failed to send friend request.',
                errors=str(e)
            )
            return result.http_response(status=500)

    @action(detail=True, methods=['put'], url_path='accept')
    def accept_request(self, request, pk=None):
        try:
            print(f"Accept request called with pk: {pk}")
            friend_request = self.get_object()
            if friend_request.to_user != request.user:
                return Response({'error': 'Cannot accept request for another user.'}, status=status.HTTP_400_BAD_REQUEST)

            friend_request.status = 'accepted'
            friend_request.save()
            Friendship.objects.create(user1=friend_request.from_user, user2=friend_request.to_user)

            logger.info(f"Friend request from {friend_request.from_user} accepted successfully.")
            result = SuccessResponse(
                code=200,
                status='SUCCESS',
                message='Friend request accepted successfully.'
            )
            return result.http_response()

        except ValueError as ve:
            logger.error(f"Error accepting friend request: {ve}")
            result = ErrorResponse(
                code=status.HTTP_400_BAD_REQUEST,
                status='BAD_REQUEST',
                message=str(ve),
                errors=str(ve)
            )
            return result.http_response(status=400)

        except Http404:
            logger.error(f"Friend request with id does not exist.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='Friend request not found.',
                errors='NOT_FOUND'
            )
            return result.http_response(status=404)

        except Exception as e:
            logger.error(f"An error occurred while updating the user.: {e}")
            result = ErrorResponse(
                code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                status='INTERNAL_SERVER_ERROR',
                message='An error occurred while updating the user.',
                errors=str(e)
            )
            return result.http_response(status=500)

    @action(detail=True, methods=['delete'], url_path='reject')
    def reject_request(self, request, pk=None):
        try:
            friend_request = self.get_object()
            if friend_request.to_user != request.user:
                return Response({'error': 'Cannot reject request for another user.'}, status=status.HTTP_400_BAD_REQUEST)

            friend_request.delete()
            logger.info(f"Friend request from {friend_request.from_user} to {friend_request.to_user} rejected successfully.")
            result = SuccessResponse(
                    code=200,
                    status='SUCCESS',
                    message='Friend request rejected successfully.'
                )
            return result.http_response(status=200)

        except Http404:
            logger.error(f"Friend request with from_user={friend_request.from_user} and to_user={request.user.id} does not exist.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='Friend request not found.',
                errors='No Data found'
            )
            return result.http_response(status=404)

        except ValueError as ve:
            logger.error(f"Error rejecting friend request: {ve}")
            result = ErrorResponse(
                code=status.HTTP_403_FORBIDDEN,
                status='FORBIDDEN',
                message=str(ve),
                errors=str(ve)
            )
            return result.http_response(status=403)

        except Exception as e:
            logger.error(f"Error rejecting friend request: {e}")
            result = ErrorResponse(
                code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                status='INTERNAL_SERVER_ERROR',
                message='Failed to reject friend request.',
                errors=str(e)
            )
            return result.http_response(status=500)

           
class FriendListView(generics.ListAPIView):
    serializer_class = UserSerializer
    pagination_class = UserPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        accepted_users2 = Friendship.objects.filter(user2=user).values_list('user1', flat=True)
        requested_user1 = Friendship.objects.filter(user1=user).values_list('user2', flat=True)
        accepted_users = list(set(accepted_users2).union(set(requested_user1)))
        friends = User.objects.filter(id__in = accepted_users)
        return friends

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            if page is None:
                logger.error("Invalid page requested.")
                result = ErrorResponse(
                    code=status.HTTP_400_BAD_REQUEST,
                    status='BAD_REQUEST',
                    message='Invalid page.',
                    errors='The requested page does not exist.'
                )
                return result.http_response(status=status.HTTP_400_BAD_REQUEST)
            
            serialized_data = self.serializer_class(page, many=True).data
            
            next_page_url = paginator.get_next_link()
            prev_page_url = paginator.get_previous_link()
            logger.info("Accepted friends list fetched successfully.")
            result = SuccessResponse(
                code=200,
                status='SUCCESS',
                message='Accepted friends list fetched successfully.',
                data=serialized_data,
                next_page=next_page_url,
                previous_page=prev_page_url
            )
            return result.http_response(status=200)

        except User.DoesNotExist:
            logger.error("User does not exist.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='User not found.',
                error='Users not found.'
            )
            return result.http_response(status=404)

        except Http404:
            logger.error("No data with this Id.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='No data with this Id.',
                error='NOT_FOUND.'
            )
            return result.http_response(status=404)

        except Exception as e:
            logger.error(f"Failed due to: {str(e)}")
            result = ErrorResponse(
                code=status.HTTP_400_BAD_REQUEST,
                status='BAD_REQUEST',
                message='Failed to retrieve accepted friends list.',
                errors=str(e)
            )
            return result.http_response(status=400)

class PendingFriendRequestListView(generics.ListAPIView):
    serializer_class = UserSerializer
    pagination_class = UserPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        pending_users = FriendRequest.objects.filter(to_user=user, status='pending').values_list('from_user', flat=True)
        users = User.objects.filter(id__in = pending_users)
        return users

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            if page is None:
                logger.error("Invalid page requested.")
                result = ErrorResponse(
                    code=status.HTTP_400_BAD_REQUEST,
                    status='BAD_REQUEST',
                    message='Invalid page.',
                    errors='The requested page does not exist.'
                )
                return result.http_response(status=status.HTTP_400_BAD_REQUEST)
            
            serialized_data = self.serializer_class(page, many=True).data
            
            next_page_url = paginator.get_next_link()
            prev_page_url = paginator.get_previous_link()

            logger.info("Pending friend requests list fetched successfully.")
            result = SuccessResponse(
                code=200,
                status='SUCCESS',
                message='Pending friend requests list fetched successfully.',
                data=serialized_data,
                next_page=next_page_url,
                previous_page=prev_page_url
            )
            return result.http_response(status=200)

        except FriendRequest.DoesNotExist:
            logger.error("Friend request does not exist.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='Friend request not found.',
                errors='NOT_FOUND'
            )
            return result.http_response(status=404)

        except Http404:
            logger.error("No data with this Id.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='No data with this Id.',
                errors='No data with this Id.'
            )
            return result.http_response(status=404)

        except Exception as e:
            logger.error(f"Failed due to: {str(e)}")
            result = ErrorResponse(
                code=status.HTTP_400_BAD_REQUEST,
                status='BAD_REQUEST',
                message='Failed to retrieve pending friend requests list.',
                errors=str(e)
            )
            return result.http_response(status=400)
        
class UsersToSendFriendRequestView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = UserPagination

    def get_queryset(self):
        user = self.request.user
        user1_ids = Friendship.objects.filter(user1=user).values_list('user2', flat=True)
        user2_ids = Friendship.objects.filter(user2=user).values_list('user1', flat=True)
        friend_ids = set(user1_ids).union(set(user2_ids))
        return User.objects.exclude(id=user.id).exclude(id__in=friend_ids)

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()

            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            if page is None:
                logger.error("Invalid page requested.")
                result = ErrorResponse(
                    code=status.HTTP_400_BAD_REQUEST,
                    status='BAD_REQUEST',
                    message='Invalid page.',
                    errors='The requested page does not exist.'
                )
                return result.http_response(status=status.HTTP_400_BAD_REQUEST)
            
            serialized_data = self.serializer_class(page, many=True).data
            
            next_page_url = paginator.get_next_link()
            prev_page_url = paginator.get_previous_link()

            logger.info("Users to send friend requests fetched successfully.")
            result = SuccessResponse(
                code=200,
                status='SUCCESS',
                message='Users fetched successfully.',
                data=serialized_data,
                next_page=next_page_url,
                previous_page=prev_page_url
            )
            return result.http_response(status=200)

        except User.DoesNotExist:
            logger.error("User does not exist.")
            result = ErrorResponse(
                code=status.HTTP_404_NOT_FOUND,
                status='NOT_FOUND',
                message='Users not found.',
                errors='Users not found.'
            )
            return result.http_response(status=404)

        except Exception as e:
            logger.error(f"Failed due to: {str(e)}")
            result = ErrorResponse(
                code=status.HTTP_400_BAD_REQUEST,
                status='BAD_REQUEST',
                message='Failed to retrieve users.',
                errors=str(e)
            )
            return result.http_response(status=400)

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    pagination_class = UserPagination
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            if not queryset.exists():
                logger.error("No Data Found.")
                result = ErrorResponse(
                    code=status.HTTP_404_NOT_FOUND,
                    status='NOT_FOUND',
                    message='No users found.',
                    errors='No users match the given filter.'
                )
                return result.http_response(status=status.HTTP_404_NOT_FOUND)
            
            paginator = self.pagination_class()
            page = paginator.paginate_queryset(queryset, request)
            if page is None:
                logger.error("Invalid page requested.")
                result = ErrorResponse(
                    code=status.HTTP_400_BAD_REQUEST,
                    status='BAD_REQUEST',
                    message='Invalid page.',
                    errors='The requested page does not exist.'
                )
                return result.http_response(status=status.HTTP_400_BAD_REQUEST)
            
            serialized_data = self.serializer_class(page, many=True).data
            
            next_page_url = paginator.get_next_link()
            prev_page_url = paginator.get_previous_link()

            logger.info("Data fetched successfully.")
            result= SuccessResponse(
                code=200,
                status='FETCHED',
                message="Users fetched successfully.",
                data=serialized_data,
                next_page=next_page_url,
                previous_page=prev_page_url
                )
            return result.http_response(status=200) 
        
        except Http404:
            logger.error("No Data Found")
            result= ErrorResponse(code=status.HTTP_404_NOT_FOUND,status='NOT_FOUND',message='No Data Found',errors='No Data Found')
            return result.http_response(status=404) 

        except Exception as e:
            logger.error(f"Error: {e}")
            result= ErrorResponse(code=status.HTTP_500_INTERNAL_SERVER_ERROR,status='INTERNAL_SERVER_ERROR',message="Something went wrong",errors=f'{e}')
            return result.http_response(status=500)  
        
class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        user_id = kwargs.get('pk')
        try:
            user = self.get_object()
            serializer = self.get_serializer(user)
            logger.info(f"User with id {user_id} fetched successfully.")
            result= SuccessResponse(code=status.HTTP_200_OK,status='OK',message="Users fetched successfully.",data= serializer.data)
            return result.http_response(status=200) 
        
        except Http404:
            logger.error("No Data Found")
            result= ErrorResponse(code=status.HTTP_404_NOT_FOUND,status='NOT_FOUND',message='No Data Found',errors='No Data Found')
            return result.http_response(status=404) 

        except Exception as e:
            logger.error(f"Error: {e}")
            result= ErrorResponse(code=status.HTTP_500_INTERNAL_SERVER_ERROR,status='INTERNAL_SERVER_ERROR',message="Something went wrong",errors=f'{e}')
            return result.http_response(status=500) 
       
    def put(self, request, *args, **kwargs):
        user_id = kwargs.get('pk')
        try:
            user = self.get_object()
            serializer = self.get_serializer(user, data=request.data, partial=False)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            logger.info(f"User with id {user_id} updated successfully.")
            result= SuccessResponse(code=status.HTTP_200_OK,status='OK',message="Users fetched successfully.",data= serializer.data)
            return result.http_response(status=200) 
        
        except Http404:
            logger.error(f"User with id {user_id} not found.")
            result= ErrorResponse(code=status.HTTP_404_NOT_FOUND,status='NOT_FOUND',message='No Data Found',errors='No Data Found')
            return result.http_response(status=404) 
        
        except ValidationError as ve:
            logger.error(f"Validation error updating user with id {user_id}: {ve}")
            result= ErrorResponse(code=status.HTTP_400_BAD_REQUEST,status='BAD_REQUEST',message='No Data Found',errors=ve.message_dict)
            return result.http_response(status=400) 

        except Exception as e:
            logger.error(f"Unexpected error updating user with id {user_id}: {e}")
            result= ErrorResponse(code=status.HTTP_500_INTERNAL_SERVER_ERROR,status='INTERNAL_SERVER_ERROR',message='Unexpected error occurred while updating user.',errors='No Data Found')
            return result.http_response(status=500) 
        
    def delete(self, request, *args, **kwargs):
        user_id = kwargs.get('pk')
        try:
            user = self.get_object()
            user_data = self.get_serializer(user).data
            self.perform_destroy(user)
            logger.info(f"User with id {user_id} deleted successfully.")
            result= SuccessResponse(code=status.HTTP_204_NO_CONTENT,status='NO_CONTENT',message="User Deleted Successfully.",data= user_data)
            return result.http_response(status=204) 

        except Http404:
            logger.error(f"User with id {user_id} not found.")
            result= ErrorResponse(code=status.HTTP_404_NOT_FOUND,status='NOT_FOUND',message='No Data Found',errors='No Data Found')
            return result.http_response(status=404)
        
        except Exception as e:
            logger.error(f"Unexpected error updating user with id {user_id}: {e}")
            result= ErrorResponse(code=status.HTTP_500_INTERNAL_SERVER_ERROR,status='INTERNAL_SERVER_ERROR',message='Unexpected error occurred while updating user.',errors='No Data Found')
            return result.http_response(status=500) 
