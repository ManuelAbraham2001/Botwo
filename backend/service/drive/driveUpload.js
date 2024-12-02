const { google } = require('googleapis');
const { authorize } = require('../../authv2');
const fs = require("fs");
const path = require("path");
const https = require("https");

async function upload(phone, url, filename = `file_${new Date().toISOString()}`) {
    try {
        const auth = await authorize(phone); // Autoriza el acceso
        const drive = google.drive({ version: 'v3', auth });

        // Descargar el archivo y obtener el tipo MIME
        const { contentType, filePath } = await downloadFile(
            url
        );

        console.log("Archivo descargado en:", filePath);
        console.log("Tipo MIME:", contentType);

        // Preparar metadatos y flujo para Google Drive
        const fileMetadata = {
            name: path.basename(filename), // Nombre que tendrá en Google Drive
        };
        const media = {
            mimeType: contentType, // Tipo MIME del archivo
            body: fs.createReadStream(filePath), // Stream del archivo
        };

        // Subir el archivo a Google Drive
        const response = await drive.files.create({
            requestBody: fileMetadata,
            media: media,
            fields: 'id',
        });
        fs.unlinkSync(filePath)
        console.log("File ID:", response.data.id);
        return 'Archivo subido con exito'
    } catch (error) {
        console.error("Error en la carga:", error);
        return 'Ocurrio un error al cargar el archivo'
    }
}

const downloadFile = async (url) => {
    const twilioAuth = Buffer.from(`${process.env.TWILIO_USER}:${process.env.AUTH_TOKEN}`).toString("base64");

    const options = {
        headers: {
            Authorization: `Basic ${twilioAuth}`,
        },
    };

    return new Promise((resolve, reject) => {
        const handleRequest = (url) => {
            https.get(url, options, (response) => {
                if (response.statusCode === 307 || response.statusCode === 302) {
                    // Si hay redirección, seguir la nueva URL
                    const newUrl = response.headers.location;
                    handleRequest(newUrl); // Llama de nuevo con la nueva URL
                    return;
                }

                if (response.statusCode !== 200) {
                    reject(new Error(`Error: HTTP ${response.statusCode}`));
                    return;
                }

                // Obtener el tipo MIME del archivo
                const contentType = response.headers['content-type'];
                console.log(`Content-Type recibido: ${contentType}`);

                // Mapear tipo MIME a extensión de archivo
                const extension = contentType.split('/')[1] || 'bin';
                const destination = path.join(__dirname, `file.${extension}`);
                console.log('Destino del archivo:', destination);

                const file = fs.createWriteStream(destination);

                response.pipe(file);

                file.on('finish', () => {
                    file.close(() => {
                        console.log(`Descarga completada exitosamente: ${destination}`);
                        resolve({ contentType, filePath: destination }); // Resolver con tipo MIME y ruta del archivo
                    });
                });

                file.on('error', (err) => {
                    fs.unlink(destination, () => reject(err));
                });
            }).on('error', (err) => reject(err));
        };

        // Inicia la solicitud
        handleRequest(url);
    });
};

module.exports = {upload}