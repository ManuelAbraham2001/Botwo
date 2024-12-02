const { google } = require('googleapis');
const { authorize } = require("../../authv2");

// Función para consultar horarios disponibles
async function checkAvailability(phone, calendarId, startTime, endTime) {
  
  try {
    const auth = await authorize(phone);
    const calendar = google.calendar({ version: 'v3', auth });

    const response = await calendar.freebusy.query({
      requestBody: {
        timeMin: startTime, // Inicio del rango
        timeMax: endTime,   // Fin del rango
        timeZone: 'GMT-3',    // Ajusta la zona horaria si es necesario
        items: [{ id: calendarId }], // Lista de calendarios a consultar
      },
    });

    const busyTimes = response.data.calendars[calendarId].busy;

    if (busyTimes.length === 0) {
      console.log('El usuario está disponible en todo el rango especificado.');
      return 'El usuario está disponible en todo el rango especificado'
    }

    const res = busyTimes.map(bt => (`Inicio: ${bt.start}, Fin: ${bt.end}`))
    
    return res;

    // Puedes analizar los horarios ocupados para determinar las ventanas libres
  } catch (error) {
    console.error('Error al comprobar disponibilidad:', error);
  }
}

module.exports = {checkAvailability}