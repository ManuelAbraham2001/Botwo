const { google } = require('googleapis');
const { authorize } = require('../../authv2');

async function createEvent(phone, summary, location = "", description = "", startDateTime, endDateTime, timeZone = "GMT", attendees = []) {
  const auth = await authorize(phone);
  const calendar = google.calendar({ version: 'v3', auth });

  const event = {
    summary,
    location,
    description,
    start: {
      dateTime: startDateTime,
      timeZone,
    },
    end: {
      dateTime: endDateTime,
      timeZone,
    },
    attendees: attendees.map(email => ({ email })), // Convert array of emails to attendees format
    reminders: {
      useDefault: true, // Default reminders
    },
  };

  try {
    const response = await calendar.events.insert({
      calendarId: 'primary',
      resource: event,
    });
    console.log(response);
    
    return response.data; // Return the created event details
  } catch (error) {
    console.error("Error creating event:", error);
    throw new Error("Failed to create event");
  }
}

module.exports = { createEvent }