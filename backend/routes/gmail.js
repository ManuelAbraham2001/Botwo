const express = require('express');
const { markAllAsRead } = require('../service/gmail/gmailCheck');
const { listEmails } = require('../service/gmail/gmailList');
const { searchEmails } = require('../service/gmail/gmailSearch');
const { sendEmail } = require('../service/gmail/gmailSend');
const { validateJwtToken } = require('../middleware/jwt');
const router = express.Router();

router.get('/markAsRead', async (req, res) => {
    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await markAllAsRead(phone)
        res.json({ message: response })
    } catch (e) {
        console.log(e);
        
        res.json({ message: "Error al marcar los correso como leidos." })
    }
});

router.get('/list', async (req, res) => {
    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await listEmails(phone)
        res.json({ message: response })
    } catch (e) {
        return res.json({ message: "Error al listar los emails." })
    }
})

router.get('/search', async (req, res) => {
    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await searchEmails(phone, req.query.searchTerm)
        res.json({ message: response })
    } catch (e) {
        return res.json({ message: "Error al listar los emails." })
    }
})

router.post('/send', async (req, res) => {
    try {
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await sendEmail(phone, req.body.addressees, req.body.subject, req.body.text);
        res.json({ message: response })
    } catch (e) {
        return res.json({ message: "Error al listar los emails." })
    }
})


module.exports = router;


