const { google } = require('googleapis');
const mysql = require('mysql2/promise');
const { validateJwtToken } = require('./middleware/jwt');
const OAuth2Client = google.auth.OAuth2;

const SCOPES = [
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/photoslibrary',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/meetings.space.created'
];

const oAuth2Client = new OAuth2Client(process.env.CLIENT_ID, process.env.CLIENT_SECRET, process.env.REDIRECT_URI);

// Configuración de conexión a la base de datos
const dbPool = mysql.createPool({
    socketPath: process.env.HOST,   // Socket Unix de Cloud SQL
    user: process.env.USER,        // Usuario de la base de datos
    password: process.env.PASSWORD,// Contraseña de la base de datos
    database: process.env.DATABASE,// Nombre de la base de datos
    waitForConnections: true,      // Espera por conexiones libres en el pool
    connectionLimit: 10,           // Número máximo de conexiones en el pool
    queueLimit: 0                  // Sin límite para la cola de solicitudes
});

const firstInteraction = async (phone) => {
    // recupera el usuario desde la db por el numero de telefono para comprobar si es la primera vez que habla con el bot
    // en caso de que sea su primera vez, se lo reenvia al flujo de autenticacion y posteriormente se guarda el token y el telefono
    // en caso de que no sea su primera vez sigue con el flujo normal 
    try {
        if (!phone) {
            throw new Error('SID o WaId está vacío o no definido.');
        }

        const connection = await dbPool.getConnection();

        const [rows] = await connection.execute(
            'SELECT * FROM bot_workspace.users WHERE phone = ?',
            [phone]
        );

        connection.release(); // Libera la conexión para reutilizarla en el pool

        if (rows.length === 0) {
            return true; // Primera interacción
        } else {
            console.log('El usuario ya interactuó anteriormente.');
            return false; // No es la primera interacción
        }
    } catch (error) {
        console.error('Error en la comprobación de la primera interacción:', error);
        throw error;
    }
}

/**
 * Función para obtener la URL de autenticación de Google
 * para redirigir al usuario y solicitar permisos.
 */
function getAuthUrl(SID, token) {

    const { phone } = validateJwtToken(token)
    
    const state = JSON.stringify({ SID, phone });
    return oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        prompt: 'consent', // garantiza que se obtenga el refresh token en cada autorización
        state: Buffer.from(state).toString('base64')
    });
}

/**
 * Función para obtener un token de acceso y refresh token después de la autenticación.
 * @param {string} code - El código de autorización devuelto por Google.
 * @param {string} phone - El código de autorización devuelto por Google.
 * 
 */
async function getTokenFromCode(code, state) {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    const { SID, phone } = JSON.parse(Buffer.from(state, 'base64').toString());
    console.log('getTokenFromCode:', phone);
    
    // Guarda `tokens.refresh_token` en la base de datos
    await saveRefreshToken(phone, tokens.refresh_token); // Puedes ajustar 'default_user' según el caso

    return tokens.access_token;
}

/**
 * Guarda el refresh token en la base de datos.
 * @param {string} phone - Identificador del usuario.
 * @param {string} refreshToken - El refresh token devuelto por Google.
 */
async function saveRefreshToken(phone, refreshToken) {
    console.log("saveRefreshToken:", phone);
    
    try {
        const connection = await dbPool.getConnection();

        const [rows] = await connection.execute(
            `SELECT * FROM bot_workspace.users WHERE phone = ?`,
            [phone]
        );

        let result;

        if (rows.length > 0) {
            [result] = await connection.execute(
                `UPDATE bot_workspace.users SET refresh_token = ? WHERE phone = ?`,
                [refreshToken, phone]
            );
        } else {
            [result] = await connection.execute(
                `INSERT INTO bot_workspace.users (phone, refresh_token) VALUES (?, ?)`,
                [phone, refreshToken]
            );
        }

        connection.release(); // Libera la conexión para reutilizarla en el pool
        return result;
    } catch (error) {
        console.error('Error al guardar o actualizar el refresh token en la base de datos:', error);
        throw error;
    }
}


/**
 * Carga el refresh token desde la base de datos y refresca el access token.
 */
async function authorize(phone) {
    const refreshToken = await getRefreshTokenFromDB(phone);

    if (!refreshToken) {
        throw new Error('No se encontró un refresh token. Se necesita autenticar al usuario.');
    }

    oAuth2Client.setCredentials({ refresh_token: refreshToken });

    oAuth2Client.on('tokens', (tokens) => {
        if (tokens.refresh_token) {
            saveRefreshToken(phone, tokens.refresh_token); // Actualizar en la base de datos
        }
    });

    return oAuth2Client;
}

/**
 * Obtiene el refresh token desde la base de datos.
 * @param {string} phone - Identificador del usuario.
 * @return {Promise<string|null>}
 */
async function getRefreshTokenFromDB(phone) {
    try {
        const connection = await dbPool.getConnection();
        const [rows] = await connection.execute(
            `SELECT refresh_token FROM bot_workspace.users WHERE phone = ?`,
            [phone]
        );

        connection.release(); // Libera la conexión para reutilizarla en el pool

        return rows.length > 0 ? rows[0].refresh_token : null;
    } catch (error) {
        console.error('Error al obtener el refresh token desde la base de datos:', error);
        return null;
    }
}

module.exports = { getAuthUrl, getTokenFromCode, authorize, firstInteraction };
