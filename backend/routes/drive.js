const express = require('express');
const router = express.Router();
const { deleteFileByName } = require('../service/drive/driveDelete');
const { upload } = require('../service/drive/driveUpload');
const { list } = require('../service/drive/driveSearch');
const { validateJwtToken } = require('../middleware/jwt');

router.get('/list', async (req, res) => {
    try{
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await list(phone, req.query.searchTerm)
        return res.json({files: response.data})
    }catch(e){
        res.json({message: 'Error al buscar el archivo'})
    }
});

router.post('/upload', async (req, res) => {
    try{
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await upload(phone, req.body.url, req.body?.filename)
        return res.json({message: response})
    }catch(e){
        return res.json({message: "Error al subir el archivo"})
    }
});

router.get('/delete', async (req, res) => {
    try{
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await deleteFileByName(phone, req.query.searchTerm)
        return res.json({message: response})
    }catch(e){
        return res.status(500)
    }
});


module.exports = router;