const { google } = require('googleapis');
const { VertexAI } = require('@google-cloud/vertexai'); 
const { authorize } = require('../../authv2');

const project = 'dataflow-workshop-rubik';
const region = 'us-central1';
const textModel = 'gemini-1.5-pro-002';

async function modifyEvent(phone, eventName, eventDate, updatedFields, participants = [], removeParticipants = false) {
    const vertexAI = new VertexAI({ project: project, location: region });

    const generativeTextModel = vertexAI.preview.getGenerativeModel({
        model: textModel,
        generationConfig: { responseMimeType: "application/json" }
    });

    try {
        const auth = await authorize(phone);
        const calendar = google.calendar({ version: 'v3', auth });

        // Obtener eventos en la fecha especificada
        const startOfDay = new Date(eventDate).toISOString();
        const endOfDay = new Date(new Date(eventDate).setDate(new Date(eventDate).getDate() + 1)).toISOString();

        const response = await calendar.events.list({
            calendarId: 'primary',
            timeMin: startOfDay,
            timeMax: endOfDay,
            singleEvents: true,
            orderBy: 'startTime',
        });

        const events = response.data.items;

        console.log(events);

        if (events.length === 0) {
            console.log('No se encontraron eventos en la fecha especificada.');
            return;
        }
        
        const eventsObj = events.map(e => ({ summary: e.summary }));

        const parts = [{ text: `identifica y devolve (el formato de la respuesta que sea solo el summary en texto plano, asi {summary: 'titulo del evento'}) de este array de objetos de subjets, el que más se acerque al que busca el usuario por el Summary: '${eventName}', fuente de búsqueda: ${JSON.stringify(eventsObj)}` }];

        const request = { contents: [{ role: 'user', parts }] };

        const result = await generativeTextModel.generateContent(request);

        const event = JSON.parse(result.response.candidates[0].content.parts[0].text);

        const eventToModify = events.find(e => e.summary === event.summary);

        if (!eventToModify) {
            console.log('No se encontró un evento que coincida con el nombre proporcionado.');
            return;
        }

        // Obtener los asistentes actuales
        let attendees = eventToModify.attendees || [];

        if (removeParticipants) {
            // Eliminar participantes especificados de la lista de asistentes
            attendees = attendees.filter(attendee => !participants.includes(attendee.email));
        } else {
            // Agregar nuevos participantes sin eliminar los existentes
            participants.forEach(email => {
                if (!attendees.some(attendee => attendee.email === email)) {
                    attendees.push({ email });
                }
            });
        }

        // Actualizar el evento con los nuevos campos y asistentes
        const updatedEvent = {
            ...eventToModify,
            ...updatedFields, // Sobrescribe campos existentes con los nuevos valores
            attendees,
        };

        calendar.events.update({
            calendarId: 'primary',
            eventId: eventToModify.id,
            resource: updatedEvent,
            sendUpdates: 'all', // Notifica a los invitados sobre los cambios
        });

        return `Evento "${eventName}" modificado exitosamente.`
    } catch (error) {
        console.error('Error al buscar o modificar el evento:', error);
        return `Error al buscar o modificar el evento "${eventName}".`
    }
}

module.exports = {modifyEvent}

