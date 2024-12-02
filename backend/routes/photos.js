const express = require('express');
const { authorize } = require('../authv2');
const { extractTextFromImage } = require('../service/photos/photosExtractText');
const router = express.Router();
const {SpacesServiceClient} = require('@google-apps/meet').v2;

router.post('/extractText', async (req, res) => {
    try{
        const response = await extractTextFromImage(req.body.url)
        return res.json({text: response})
    }catch(e){
        console.log(e);
        return res.json({message: "Ocurrio un error"})
    }
});

module.exports = router;