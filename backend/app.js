const express = require('express');
const app = express();

// Middleware de Express para analizar JSON y datos en el cuerpo de las solicitudes
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Importar y usar rutas
const calendar = require('./routes/calendar');
const meet = require('./routes/meet');
const drive = require('./routes/drive');
const translate = require('./routes/translate');
const photos = require('./routes/photos');
const gmail = require('./routes/gmail');
const main = require('../src/app');

app.use('/', main);
app.use('/calendar', calendar);
app.use('/meet', meet);
app.use('/drive', drive);
app.use('/translate', translate);
app.use('/photos', photos);
app.use('/gmail', gmail);

// Manejo de errores (middleware final)
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Ocurrió un error en el servidor' });
});

module.exports = app;
