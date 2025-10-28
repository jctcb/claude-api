"""
Conners Group AI Assistant - Calendar Integration
Google Calendar integration for managing events
"""

import os
from pathlib import Path
import pickle

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("Warning: Google Calendar API libraries not installed.")

from datetime import datetime, timedelta

CALENDAR_SCOPES = ['https://www.googleapis.com/auth/calendar']

class CalendarIntegration:
    """Handles Google Calendar integration"""
    
    def __init__(self):
        self.calendar_service = None
        self.credentials_path = Path('credentials')
        self.credentials_path.mkdir(exist_ok=True)
    
    def authenticate(self):
        """Authenticate with Google Calendar API"""
        try:
            creds = None
            token_path = self.credentials_path / 'calendar_token.pickle'
            
            if token_path.exists():
                with open(token_path, 'rb') as token:
                    creds = pickle.load(token)
            
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    credentials_json = self.credentials_path / 'calendar_credentials.json'
                    if not credentials_json.exists():
                        raise Exception("Calendar credentials file not found")
                    
                    flow = InstalledAppFlow.from_client_secrets_file(
                        str(credentials_json), CALENDAR_SCOPES)
                    creds = flow.run_local_server(port=0)
                
                with open(token_path, 'wb') as token:
                    pickle.dump(creds, token)
            
            self.calendar_service = build('calendar', 'v3', credentials=creds)
            return True
        except Exception as e:
            raise Exception(f"Calendar authentication failed: {str(e)}")
    
    def get_events(self, max_results=10, time_min=None, time_max=None):
        """Get calendar events"""
        try:
            if not self.calendar_service:
                self.authenticate()
            
            if not time_min:
                time_min = datetime.utcnow().isoformat() + 'Z'
            
            events_result = self.calendar_service.events().list(
                calendarId='primary',
                timeMin=time_min,
                maxResults=max_results,
                singleEvents=True,
                orderBy='startTime'
            ).execute()
            
            events = events_result.get('items', [])
            
            formatted_events = []
            for event in events:
                start = event['start'].get('dateTime', event['start'].get('date'))
                end = event['end'].get('dateTime', event['end'].get('date'))
                
                formatted_events.append({
                    'id': event['id'],
                    'summary': event.get('summary', 'No Title'),
                    'description': event.get('description', ''),
                    'start': start,
                    'end': end,
                    'location': event.get('location', ''),
                    'attendees': [a.get('email') for a in event.get('attendees', [])]
                })
            
            return formatted_events
        except Exception as e:
            raise Exception(f"Calendar API error: {str(e)}")
    
    def create_event(self, summary, start_time, end_time, description='', location='', attendees=None):
        """Create a new calendar event"""
        try:
            if not self.calendar_service:
                self.authenticate()
            
            event = {
                'summary': summary,
                'description': description,
                'location': location,
                'start': {
                    'dateTime': start_time,
                    'timeZone': 'UTC',
                },
                'end': {
                    'dateTime': end_time,
                    'timeZone': 'UTC',
                },
            }
            
            if attendees:
                event['attendees'] = [{'email': email} for email in attendees]
            
            event = self.calendar_service.events().insert(
                calendarId='primary',
                body=event
            ).execute()
            
            return {
                'success': True,
                'event_id': event['id'],
                'link': event.get('htmlLink')
            }
        except Exception as e:
            raise Exception(f"Error creating event: {str(e)}")
    
    def update_event(self, event_id, **kwargs):
        """Update an existing event"""
        try:
            if not self.calendar_service:
                self.authenticate()
            
            event = self.calendar_service.events().get(
                calendarId='primary',
                eventId=event_id
            ).execute()
            
            if 'summary' in kwargs:
                event['summary'] = kwargs['summary']
            if 'description' in kwargs:
                event['description'] = kwargs['description']
            if 'start_time' in kwargs:
                event['start'] = {'dateTime': kwargs['start_time'], 'timeZone': 'UTC'}
            if 'end_time' in kwargs:
                event['end'] = {'dateTime': kwargs['end_time'], 'timeZone': 'UTC'}
            
            updated_event = self.calendar_service.events().update(
                calendarId='primary',
                eventId=event_id,
                body=event
            ).execute()
            
            return {
                'success': True,
                'event_id': updated_event['id']
            }
        except Exception as e:
            raise Exception(f"Error updating event: {str(e)}")
    
    def delete_event(self, event_id):
        """Delete a calendar event"""
        try:
            if not self.calendar_service:
                self.authenticate()
            
            self.calendar_service.events().delete(
                calendarId='primary',
                eventId=event_id
            ).execute()
            
            return {'success': True}
        except Exception as e:
            raise Exception(f"Error deleting event: {str(e)}")

calendar_integration = CalendarIntegration()