function validateEnvParam(paramName) {
    return (req, res, next) => {
        const paramValue = req.body[paramName]; // Valor del parámetro en el body
        const envValue = process.env.TWILIO_USER; // Valor de la variable de entorno

        // Verificar si el parámetro existe y coincide con la variable de entorno
        if (!paramValue || paramValue !== envValue) {
            return res.status(403).json({
                message: `El parámetro '${paramName}' es inválido o no coincide.`,
            });
        }

        // Continuar al siguiente middleware si todo está bien
        next();
    };
}

module.exports = validateEnvParam;
