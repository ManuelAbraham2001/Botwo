const { google } = require('googleapis');
const stringSimilarity = require('string-similarity'); // npm install string-similarity
const { authorize } = require('../../authv2');

async function deleteFileByName(phone, searchTerm) {
    try {
        const auth = await authorize(phone);
        const drive = google.drive({ version: 'v3', auth });

        const response = await drive.files.list({
            q: `name contains '${searchTerm}' and trashed=false`,
            fields: 'files(id, name)',
            spaces: 'drive',
        });

        const files = response.data.files;

        if (files.length === 0) {
            console.log(`No se encontraron archivos que coincidan con "${searchTerm}".`);
            return;
        }

        console.log('Archivos encontrados:', files.map(f => f.name));

        // Lógica de similitud para encontrar el archivo más relevante
        const fileNames = files.map(file => file.name);
        let moreThanOneMatch = false
        let matchCount = 0
        const bestMatch = stringSimilarity.findBestMatch(searchTerm, fileNames);

        bestMatch.ratings.forEach(r => {
            if(r.rating > 0.5){
                matchCount++
            }
        })

        matchCount > 1 ? moreThanOneMatch = true : moreThanOneMatch = false 

        if (bestMatch.bestMatch.rating < 0.5 || moreThanOneMatch) { // Ajusta el umbral según tu necesidad
            console.log('No se encontró un archivo suficientemente similar.');
            return;
        }

        const fileToDelete = files.find(file => file.name === bestMatch.bestMatch.target);

        // Eliminar el archivo más relevante
        drive.files.delete({
            fileId: fileToDelete.id,
        });

        console.log(`Archivo "${fileToDelete.name}" eliminado exitosamente.`);
        return `Archivo "${fileToDelete.name}" eliminado exitosamente.`
    } catch (error) {
        console.error('Error al eliminar el archivo:', error);
    }
}

module.exports = {deleteFileByName}