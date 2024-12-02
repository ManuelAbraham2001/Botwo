const app = require('../backend/app');

const PORT = 8080 || process.env.PORT;

app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
