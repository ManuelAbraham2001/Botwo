const { authorize } = require('../../authv2');
const {SpacesServiceClient} = require('@google-apps/meet').v2;

async function create(phone) {
    const auth = await authorize(phone);
    const meetClient = new SpacesServiceClient({
        authClient: auth
    });
    // Construct request
    const request = {

    };

    // Run request
    const response = await meetClient.createSpace(request);
    console.log(response);
    
    return response[0].meetingUri
}

module.exports = {create}