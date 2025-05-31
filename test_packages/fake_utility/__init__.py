"""
A simple utility for event handling
"""

def handle_event(event_type, data):
    """Handle various types of events"""
    return f"Handling {event_type}: {data}"

def process_events(events):
    """Process a list of events"""
    return [handle_event(e['type'], e['data']) for e in events]
