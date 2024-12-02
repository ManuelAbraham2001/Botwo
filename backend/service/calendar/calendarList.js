const { google } = require('googleapis');
const { authorize } = require('../../authv2');

async function calendarList(phone) {
    try {
        const auth = await authorize(phone);
        const calendar = google.calendar({ version: 'v3', auth });
        const response = await calendar.events.list({
            calendarId: 'primary',
            timeMin: new Date().toISOString(),
            maxResults: 10,
            singleEvents: true,
            orderBy: 'startTime',
        });

        const events = response.data.items;
        if (!events || events.length === 0) {
            return res.json({ response: 'No upcoming events found.' });
        }

        let text = '';
        events.forEach((event) => {
            const start = event.start.dateTime || event.start.date;
            text += `${start} - ${event.summary}\n`;
        });
        return { response: text }
    } catch (error) {
        console.error('Error listing events:', error);
        return 500, {message: "Error"}
    }
}

module.exports = {calendarList}
