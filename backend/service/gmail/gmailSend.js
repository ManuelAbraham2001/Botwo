const { google } = require('googleapis');
const { authorize } = require('../../authv2');

// Redactar y enviar un correo
async function sendEmail(phone, toEmails, subject, bodyHtml) {
    try {
        const signature = await getUserSignature(phone); // Obtener la firma del usuario
        const fullBodyHtml = signature ? `${bodyHtml}<br><br>--<br>${signature}` : bodyHtml;

        const authClient = await authorize(phone);
        const gmail = google.gmail({ version: 'v1', auth: authClient });

        if (!Array.isArray(toEmails) || toEmails.length === 0) {
            throw new Error('Debe proporcionar un array con al menos un destinatario.');
        }

        const to = toEmails.join(', ');

        const emailContent = [
            `To: ${to}`,
            `Subject: ${subject}`,
            'Content-Type: text/html; charset=utf-8',
            '',
            fullBodyHtml,
        ].join('\n');

        const encodedMessage = Buffer.from(emailContent)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        const response = await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: encodedMessage,
            },
        });

        return 'Correo electronico enviado con exito.';
    } catch (error) {
        console.error('Error al enviar el correo con firma HTML:', error);
        throw error;
    }
}

async function getUserSignature(phone) {
    try {
        const authClient = await authorize(phone); // Tu función de autenticación
        const gmail = google.gmail({ version: 'v1', auth: authClient });

        const response = await gmail.users.settings.sendAs.list({
            userId: 'me',
        });

        const sendAs = response.data.sendAs || [];
        const primarySendAs = sendAs.find((sendAsEntry) => sendAsEntry.isPrimary);

        if (primarySendAs && primarySendAs.signature) {
            console.log('Firma encontrada:', primarySendAs.signature);
            return primarySendAs.signature; // Devuelve la firma en HTML
        }

        console.log('No se encontró ninguna firma configurada.');
        return null;
    } catch (error) {
        console.error('Error al obtener la firma del usuario:', error);
        throw error;
    }
}

module.exports = {sendEmail}
