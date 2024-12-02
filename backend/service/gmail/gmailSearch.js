const { google } = require('googleapis');
const { authorize } = require('../../authv2');

async function searchEmails(phone, query) {
    try {
        const authClient = await authorize(phone);
        const gmail = google.gmail({ version: 'v1', auth: authClient });

        const response = await gmail.users.messages.list({
            userId: 'me',
            q: `subject:${query}`, // Ejemplo: "from:usuario@ejemplo.com subject:'Reunión'"
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
        console.error('Error al buscar correos:', error);
        throw error;
    }
}

module.exports = {searchEmails}