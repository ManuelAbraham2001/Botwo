const { authorize } = require("../../authv2");
const { google } = require('googleapis');
const { VertexAI } = require('@google-cloud/vertexai')

const project = 'dataflow-workshop-rubik';
const region = 'us-central1';
const textModel = 'gemini-1.5-pro-002';

async function cancelEvent(phone, eventName, eventDate) {

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

        console.log('eventos:', events);

        if (events.length === 0) {
            console.log('No se encontraron eventos en la fecha especificada.');
            return;
        }
        const eventsObj = events.map(e => ({ summary: e.summary }))

        console.log(eventsObj);

        const parts = [{ text: `identifica y devolve de este array de objetos de subjets (el formato de la respuesta que sea el siguiente {summary: titulo del evento}), el que mas se acerque al que busca el usuario, es decir si el usuario busca por 'reunion' y en la fuente de busqueda identificas 'reunion importante por ejemplo', devolver el summary que idintifiques de la fuente, no el del usuario. El Summary del usuario es: '${eventName}', fuente de busqueda: ${JSON.stringify(eventsObj)}` }];

        const request = { contents: [{ role: 'user', parts }] };

        const result = await generativeTextModel.generateContent(request);

        const event = JSON.parse(result.response.candidates[0].content.parts[0].text)

        console.log('event encontrado por vertex:', event);
        

        const eventToCancel = events.find(e => e.summary == event?.summary || e.summary == event.related_summary)

        console.log(eventToCancel);
        

        calendar.events.delete({
            calendarId: 'primary',
            eventId: eventToCancel.id,
            sendUpdates: 'all', // Cambiar a 'all' o 'externalOnly' si deseas notificar a los invitados
        });

        return `El evento "${eventName}" cancelado exitosamente.`
    } catch (error) {
        console.error('Error al buscar o cancelar el evento:', error);
        return `Error al buscar o cancelar el evento "${eventName}"`
    }

}

module.exports = { cancelEvent }