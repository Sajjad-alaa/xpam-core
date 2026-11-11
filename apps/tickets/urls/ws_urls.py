from django.urls import path

from .. import ws

app_name = 'tickets'

urlpatterns = [
    path('ws/tickets/events/', ws.TicketEventsWebsocket.as_asgi(), name='ticket-events-ws'),
]
