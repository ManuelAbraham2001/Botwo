const { Translate } = require('@google-cloud/translate').v2;
const express = require('express');
const router = express.Router();

router.post('/', async (req, res) => {
    const translate = new Translate();
    let [translations] = await translate.translate(req.body.text, req.body.code);
    translations = Array.isArray(translations) ? translations : [translations];
    translations.forEach((translation, i) => {
        let traduction = `${req.body.text[i]} => (${req.body.code}) ${translation}`
        console.log(`${req.body.text[i]} => (${req.body.code}) ${translation}`);
        res.json({translation: traduction})
    });
});

module.exports = router;