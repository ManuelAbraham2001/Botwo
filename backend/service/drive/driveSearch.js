const { google } = require('googleapis');
const { authorize } = require('../../authv2');

async function list(phone, searchTerm) {
    const auth = await authorize(phone);
    const service = google.drive({ version: 'v3', auth });
    const files = [];
    
    try {
        const response = await service.files.list({
            q: `name contains '${searchTerm}' and trashed=false`,
            fields: 'nextPageToken, files(id, name, resourceKey)',
            spaces: 'drive',
        });
        
        if (!response.data.files || response.data.files.length === 0) {
            return { message: 'No se encontraron archivos para el término proporcionado.', data: [] };
        }
        
        // Construir una lista de archivos con enlaces
        const filesList = response.data.files.map((file) => ({
            id: file.id,
            name: file.name,
            viewLink: `https://drive.google.com/file/d/${file.id}/view${file.resourceKey ? `?resourcekey=${file.resourceKey}` : ''}`,
            downloadLink: `https://driveusercontent.google.com/u/0/uc?id=${file.id}&export=download${file.resourceKey ? `&resourcekey=${file.resourceKey}` : ''}`,
        }));
        
        // Crear una respuesta con los detalles de los archivos
        const responseMessage = filesList
            .map((file, index) => {
                return `${index + 1}. ${file.name}\nVer: ${file.viewLink}\nDescargar: ${file.downloadLink}\n`;
            })
            .join('\n');
        
        console.log('Archivos encontrados:', filesList);
        
        return {
            message: `Se encontraron ${filesList.length} archivos:\n\n${responseMessage}`,
            data: filesList,
        };
    } catch (err) {
        // TODO(developer) - Handle error
        throw err;
    }
}

module.exports = {list}