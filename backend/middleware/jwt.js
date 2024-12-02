const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.SECRET_KEY;

function createJwtToken(payload, expiresIn = '1h') {
    try {
        const token = jwt.sign(payload, SECRET_KEY, { expiresIn });
        return token;
    } catch (error) {
        console.error('Error al generar el token JWT:', error);
        throw error;
    }
}

// Función para validar un token JWT
function validateJwtToken(token) {
    try {
        if (token.startsWith("Bearer ")) {
            const splitToken = token.split('Bearer ')[1]
            const decoded = jwt.verify(splitToken, SECRET_KEY);
            // console.log('Token JWT válido:', decoded);
            return decoded;
        } else {
            return {
                message: `Invalid token`,
            };
        }

    } catch (error) {
        console.error('Error al validar el token JWT:', error.message);
        return {
            message: `Invalid token`,
        };
    }
}


module.exports = { createJwtToken, validateJwtToken }
