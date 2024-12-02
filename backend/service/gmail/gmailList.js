const { google } = require('googleapis');
const { authorize } = require('../../authv2');

// Listar correos no leídos o más recientes
async function listEmails(phone, maxResults = 10, onlyUnread = true) {
    try {
        const authClient = await authorize(phone); // Tu función de autenticación
        const gmail = google.gmail({ version: 'v1', auth: authClient });

        const query = onlyUnread ? 'is:unread' : ''; // Filtrar solo no leídos si aplica

        const response = await gmail.users.messages.list({
            userId: 'me',
            maxResults,
            q: query,
        });

        const messages = response.data.messages || [];

        const detailedMessages = await Promise.all(
            messages.map(async (message) => {
                const messageDetails = await gmail.users.messages.get({
                    userId: 'me',
                    id: message.id,
                });

                const headers = messageDetails.data.payload.headers;
                const subjectHeader = headers.find((header) => header.name === 'Subject');
                const subject = subjectHeader ? subjectHeader.value : '(Sin asunto)';
                const link = `https://mail.google.com/mail/u/0/#inbox/${message.id}`;

                return {
                    id: message.id,
                    subject,
                    link,
                };
            })
        );

        console.log(`Se encontraron ${detailedMessages.length} correos:`);
        detailedMessages.forEach((msg) =>
            console.log(`Asunto: ${msg.subject} | Enlace: ${msg.link}`)
        );

        return detailedMessages;
        
    } catch (error) {
        console.error('Error al listar correos:', error);
        throw error;
    }
}

module.exports = {listEmails}
