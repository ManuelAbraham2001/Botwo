const { google } = require('googleapis');
const { authorize } = require('../../authv2');

// Marcar todos los correos como leídos
async function markAllAsRead(phone) {
    try {
        const authClient = await authorize(phone); // Tu función de autenticación
        const gmail = google.gmail({ version: 'v1', auth: authClient });
        
        let pageToken = null;
        let totalMessages = 0;
        let processedMessages = 0

        do {
            // Listar correos no leídos en la página actual
            const response = await gmail.users.messages.list({
                userId: 'me',
                q: 'is:unread', // Filtro para correos no leídos
                pageToken,
                maxResults: 100, // Límite de mensajes por página
            });

            const messages = response.data.messages || [];
            totalMessages += messages.length;
            pageToken = response.data.nextPageToken; // Token para la siguiente página

            if (messages.length === 0) {
                console.log('No hay más correos no leídos en esta página.');
                continue;
            }

            console.log(`Procesando ${messages.length} correos en esta página...`);

            // Procesar los mensajes lentamente
            const delay = 1000; // 1 segundo entre cada solicitud
            for (let i = 0; i < messages.length; i++) {
                setTimeout(async () => {
                    try {
                        await gmail.users.messages.modify({
                            userId: 'me',
                            id: messages[i].id,
                            requestBody: {
                                removeLabelIds: ['UNREAD'], // Eliminar la etiqueta "UNREAD"
                            },
                        });
                        processedMessages++
                    } catch (error) {
                        console.error(`Error al procesar el correo ${messages[i].id}:`, error);
                    }
                }, i * delay);
            }
        } while (pageToken);

        return `Proceso completado: ${processedMessages} correos marcados como leídos.`;

    } catch (error) {
        console.error('Error al marcar los correos como leídos:', error);
        throw error;
    }
}

module.exports = {markAllAsRead}
