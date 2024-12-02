const vision = require('@google-cloud/vision');
const fs = require("fs");
const path = require("path");
const https = require("https");

// Función para extraer texto de una imagen
async function extractTextFromImage(url) {
    const client = new vision.ImageAnnotatorClient({});
    const { contentType, filePath } = await downloadFile(
        url
    );
    try {
        // Llama a la API de Vision para detectar texto en la imagen
        const [result] = await client.textDetection(filePath);
        const detections = result.textAnnotations;

        if (!detections || detections.length === 0) {
            console.log('No se detectó texto en la imagen.');
            return '';
        }

        const extractedText = detections[0].description; // El texto completo detectado
        console.log('Texto extraído de la imagen:', extractedText);
        fs.unlinkSync(filePath)
        return extractedText;
    } catch (error) {
        console.error('Error al extraer texto de la imagen:', error);
        throw error;
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

                const file = fs.createWriteStream(destination);

                response.pipe(file);

                file.on('finish', () => {
                    file.close(() => {
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

module.exports = {extractTextFromImage}
