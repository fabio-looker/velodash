const promisify = require("promisify-node");
const express = require('express')
const path = require('path')
const _jwt = require('jsonwebtoken')
const jwt = {
		verify: promisify(_jwt.verify),
		header: (token,options={})=>_jwt.decode(token,{complete:true,...options}).header
	}
const jwkToPem = require('jwk-to-pem')
const fetch = require('node-fetch')
const http = require('http')
const parseUrl = require('url').parse

require('events').EventEmitter.defaultMaxListeners = 15 // Otherwise node warns about a possible memory leak when using pg
const pg = require('pg')
const WebSocketServer = require('ws').Server

const app = express()
const config = {
		port:3000,
		env: process.env.NODE_ENV || "dev",
		ownUrl:"http://localhost:3000/", //Should be whitelisted by OAuth2 IDP as a redirect URL
		idpPublicKeyUrl: "https://login.microsoftonline.com/common/discovery/keys",
		jwtExpectedAudience: "94072ca3-e58d-4bfc-a0c8-63fddd45d15c", //This should be the Application ID created via Azure AD App registration
		jwtExpectedIssuer: "https://sts.windows.net/d218a038-fce6-4d24-b555-da29bdb61480/", //This seems to be based on our Azure tenant Id
		idpAuthorizeUrl: (state)=>("https://login.microsoftonline.com/d218a038-fce6-4d24-b555-da29bdb61480/oauth2/authorize?response_type=token&scope=openid&resource=94072ca3-e58d-4bfc-a0c8-63fddd45d15c&client_id=94072ca3-e58d-4bfc-a0c8-63fddd45d15c&redirect_uri="+encodeURIComponent(config.ownUrl)+"&state="+encodeURIComponent(state))
	}
const pIdpPublicPemsByKid = fetch(config.idpPublicKeyUrl)
		.then(r=>r.json())
		.then(jwk=>jwk.keys.map(k=>({[k.kid]:jwkToPem(k)})).reduce((kk,k)=>({...k,...kk}),{}))



!async function (){
		console.log(config.env)
		const app = express()
		const server = http.createServer(app)
		const wss = new WebSocketServer({server,verifyClient})
		app.use(express.static(path.join(__dirname, "static/")))
		if(config.env=="dev"){app.set('json spaces',2)}
		app.use(errorHandler)
		wss.on('connection', websocketConnection)
		server.listen(config.port,
				()=>console.info('Listening on ' + config.port)
			)
		//app.listen(config.port,()=>console.log("http://localhost:"+config.port+"/"))

		return;


	}()


async function verifyClient ({req},verificationDone){
		//Per https://github.com/websockets/ws/blob/master/doc/ws.md
		//And https://github.com/websockets/ws/blob/master/examples/express-session-parse/index.js
		try{
				const token = parseUrl(req.url, true).query.token
				const idpPublicPemByKid = await pIdpPublicPemsByKid
				console.log(await jwt.header(token))
				const kid = (await jwt.header(token)).kid
				if(!idpPublicPemByKid[kid]){throw "Access token key not accepted. kid: "+kid}
				const verified = await jwt.verify(
						token,
						idpPublicPemByKid[kid],
						// ^ :facepalm: the "JSON Web Tokens" library doesn't take "JSON Web Keys"
						{
								audience: config.jwtExpectedAudience,
								issuer: config.jwtExpectedIssuer,
								algorithms: ['RS256']
							}
					)
				req.verified = verified
				verificationDone(true)
			}
		catch(err){
				console.error(err)
				verificationDone(false,403,"Unable to authorize connection")
			}
	}
async function websocketConnection(ws, req) {
		ws.send("Connect success")
		ws.on('message', async msgStr => {try{
				ws.send(JSON.stringify({st:"info",msg:"WS Response"}))
			}catch(err){
				ws.send(JSON.stringify(err)) //TODO clean up
			}})
	}
function errorHandler (err, req, res, next) {
		if(!err.status && !(err.message && err.message.status)){
				console.error("Unexpected error: ",err)
			}
		res.status(err.status || (err.message && err.message.status) || 500).json({
				error: err.message || err,
				trace:(cfg.env=='dev' && err.stack ? err.stack.split("\n") : undefined)
			})
	}
