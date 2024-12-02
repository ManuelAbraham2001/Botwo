const express = require('express');
const router = express.Router();
const { createEvent } = require('../service/calendar/calendarCreate');
const { calendarList } = require('../service/calendar/calendarList');
const { checkAvailability } = require('../service/calendar/calendarCheck');
const { cancelEvent } = require('../service/calendar/calendarDelete');
const { modifyEvent } = require('../service/calendar/calendarEdit');
const { validateJwtToken } = require('../middleware/jwt');

router.get('/list', async (req, res) => {
    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await calendarList(phone)
        return res.json(response)
    } catch (e) {
        return res.json({ message: "Error al listar los eventos." })
    }

});

router.post('/create', async (req, res) => {
    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        
        await createEvent(phone, req.body.summary, req.body?.location, req.body?.description, req.body.startDateTime, req.body.endDateTime, req.body?.timeZone, req.body?.attendees)
        return res.json({ message: "Evento creado con exito." })
    } catch (e) {
        return res.json({ message: "Error al crear el evento." })
    }
})

router.post('/availability', async (req, res) => {

    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await checkAvailability(phone, req.body.email, req.body.startDate, req.body.endDate)
        return res.json({ message: `Horarios ocupados: ${response}` })
    } catch (e) {
        return res.json({ message: "Error al crear el evento." })
    }
})

router.post('/cancel', async (req, res) => {

    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await cancelEvent(phone, req.body.eventName, req.body.eventDate)
        // console.log(response);
        return res.json({ message: response })
    } catch (e) {
        return res.json({ message: "Error al cancelar el evento." })
    }
})

router.post('/modify', async (req, res) => {
    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await modifyEvent(phone, req.body.eventName, req.body.eventDate, req.body.updatedFields, req.body.participants, req.body.removeParticipants);
        // console.log(response);
        return res.json({ message: response })
    } catch (e) {
        return res.json({ message: "Error al cancelar el evento." })
    }
})



module.exports = router;


