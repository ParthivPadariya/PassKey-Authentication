const express = require('express')
const {generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse} = require('@simplewebauthn/server')
const crypto = require('crypto')

// globalThis property provides a standard way of accessing the global this value (and hence the global object itself) across environments.
if (!globalThis.crypto) {
    globalThis.crypto = crypto
}

const PORT = 3000;
const app = express();

// The app.use(express.static('./public')) code tells Express to serve static files from the public directory.
// return index.html page (server side rendering)
app.use(express.static('./public'))
// http://localhost:3000/hello.html  -> return hello page if exist
app.use(express.json());


// in-memory
const userStore = {};
const challengeStore = {};

app.post('/register', (req,res) => {
    const { username, password } = req.body;
    const id = `user_${Date.now()}`;

    const user = {
        id,
        username,
        password
    }

    userStore[id] = user;
    console.log(`user register successfully`, userStore[id]);

    return res.send({id});
})

app.post('/register-challenge',async (req,res) => {
    const { userId } = req.body;

    if (!userStore[userId]) {
        return res.status(404).json({error: "User not Found"})
    }

    const user = userStore[userId];

    const challengePayload = await generateRegistrationOptions({
        rpID: 'localhost',
        rpName: 'My Localhost Machine',
        userName: user.username,
    })

    challengeStore[userId] = challengePayload.challenge;
    // console.log(challengePayload);
    return res.json({options: challengePayload});
})

app.post('/register-verify', async (req,res) => {
    const { userId, cred } = req.body;
    if (!userStore[userId]) {
        return res.status(404).json({error: "User not Found"})
    }

    const user = userStore[userId];
    const challenge = challengeStore[userId];

    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
    })

    if (!verificationResult.verified) {
        return res.json({error: 'could not verified'});
    }

    userStore[userId].passkey = verificationResult.registrationInfo

    return res.json({verified:true});

})

app.post('/login-challenge', async (req,res) => {
    const { userId } = req.body;
    
    const opts = await generateAuthenticationOptions({
        rpID: 'localhost'
    })

    challengeStore[userId] = opts.challenge

    return res.json({options:opts});
})

app.post('/login-verify', async (req,res) => {
    const { userId, cred } = req.body;
    
    if (!userStore[userId]) {
        return res.status(404).json({error: "User not Found"})
    }

    const user = userStore[userId];
    const challenge = challengeStore[userId];


    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
        authenticator: user.passkey
    })


    if (!result.verified) {
        return res.json({error : 'something went wrong'})
    }

    // Login user: session, cookies, jwt
    return res.json({success: true, userId});


})

app.listen(PORT, () => console.log(`Server started on ${PORT}`))