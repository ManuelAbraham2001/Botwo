const express = require('express');
const router = express.Router();
const { create } = require('../service/meet/meetCreate');
const { validateJwtToken } = require('../middleware/jwt');

router.post('/create', async (req, res) => {
    try{
        const { phone } = validateJwtToken(req.headers?.authorization)
        const response = await create(phone)
        console.log(response);
        return res.json({message: response})
    }catch(e){
        res.json({error: 500})
    }
});

module.exports = router;