var https = require('https'),
    http = require('http'),
    util = require('util'),
    path = require('path'),
    fs = require('fs'),
    colors = require('colors'),
    winston = require('winston'),
    jwt = require('jsonwebtoken'),
    url = require('url'),
    stringify = require('json-stringify-safe'),
    express = require('express'),
    moment = require('moment');
    proxy = require('http-proxy-middleware');

// verbose replacement
function logProvider(provider) {
    var logger = winston;

    var myCustomProvider = {
        log: logger.log,
        debug: logger.debug,
        info: logSplunkInfo,
        warn: logger.warn,
        error: logSplunkError
    }
    return myCustomProvider;
}

// winston.add(winston.transports.Console, {
//    timestamp: true
// });

//
// Generate token for monitoring apps
//
if (process.env.USE_AUTH_TOKEN &&
    process.env.USE_AUTH_TOKEN == "true" &&
    process.env.AUTH_TOKEN_KEY &&
    process.env.AUTH_TOKEN_KEY.length > 0) {

    var monitoringToken = jwt.sign({
        data: {nonce: "status"}
    }, process.env.AUTH_TOKEN_KEY);
    logSplunkInfo("Monitoring token: " + monitoringToken);
}

//
// Init express
//
var app = express();

// Add status endpoint
app.get('/status', function (req, res) {
    res.send("OK");
});

/**
 * A formatted array of urls retrieved from `BYPASS_CAPTCHA_URLS`.
 *
 * Formatting includes removing any leading or trailing slashes to reduce user
 * error.
 */
const bypassCaptchaURLs = process.env.BYPASS_CAPTCHA_URLS
    .replace(/ /g, '') // Remove all spaces, if any exist they're just a user entry error
    .split(',') // convert csv into array
    .map(url => url.replace(/^\/+/g, '')) // Remove leading slashes on each url if any
    .map(url => url.replace(/\/+$/, "")) // Remove trailing slashes on each url if any

console.log('BYPASS_CAPTCHA_URLS', bypassCaptchaURLs)

//
// CAPTCHA Authorization, ALWAYS first
//
app.use('/', function (req, res, next) {
    console.log('CAPTCHA1 -', req.originalUrl, '\n');

    // reg.originalURL often has multiple leading slashes, but never trailing slashes
    const formattedRequestURL = req.originalUrl.replace(/^\/+/g, '');
   
    // Bypass CAPTCHA check
    if( bypassCaptchaURLs.includes(formattedRequestURL) ){
        console.log('BYPASS CAPTCHA'); //TODO: Remove.
        return next();
    }

    // TODO: Delete additional FPC related headers, like weblogic, x-oracle, etc.
    // TODO: Get CAPTCHA validation working.
    // TODO: FPC Frontend: CAPTCHA token failing when going back and trying again (looks like it's adding multiple heaers instead of re-writing)
    // error for failure on retries:
    //
        // CAPTCHA1 - //fpcareIntegration/rest/statusCheckFamNumber

        // error: jwt verify failed, x-authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7Im5vbmNlIjoiYjIyNjUyZTQtZWZiMi1lNDgzLTJjMDItMWVhNTU0OGMxZTA0In0sImlhdCI6MTUzNTQ4NzAxNiwiZXhwIjoxNTM1NDg3OTE2fQ.m
        // vod4pnS8FQKDQGcGqadz_nGjNWq4bE4nOdnbQaUkvw,Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7Im5vbmNlIjoiZTE4MmRmNmUtNjE3Yy1kZjY0LTM3NGEtZjQzYzkyZjQ1NGQzIn0sImlhdCI6MTUzNTQ4NzAzMywiZXhwIjoxNTM1NDg3OTMzfQ.V
        // Ash57yLnJSXbeT0fkGivg26hDb_n9DTvhS7x02BMRk; err: JsonWebTokenError: jwt malformed
        // error: jwt unverifiable - access denied.  request: {"host":"mygovbc-msp-service:8080","connection":"close","content-length":"118","origin":"https://moh-fpcare-dev.pathfinder.gov.bc.ca","user-agent":"Mozilla/5.0
        // (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36","content-type":"application/json","accept":"application/json, text/plain, */*","angular":"FPC-API-Service","referer":
        // "https://moh-fpcare-dev.pathfinder.gov.bc.ca/registration-status/request-status","accept-encoding":"gzip, deflate, br","accept-language":"en-US,en;q=0.9","x-forwarded-host":"moh-fpcare-dev.pathfinder.gov.bc.ca",
        // "x-forwarded-port":"443","x-forwarded-proto":"https","forwarded":"for=142.31.57.168;host=moh-fpcare-dev.pathfinder.gov.bc.ca;proto=https","x-forwarded-for":"142.31.57.168"}
        // denyAccess: jwt unverifiable


    // Delete headers from Oracle and other middlelayer services
    delete req.headers['x-oracle-dms-ecid'];
    delete req.headers['x-oracle-dms-rid'];
    delete req.headers['x-weblogic-force-jvmid'];
    delete req.headers['breadcrumbid'];
    delete req.headers['x-weblogic-request-clusterinfo'];

    //! Tidy up above ---- orig code below

    // Log it
    // logSplunkInfo("incoming: ", req.method, req.headers.host, req.url, res.statusCode, req.headers["x-authorization"]);

    // Get authorization from browser
    var authHeaderValue = req.headers["x-authorization"];

    // Delete it because we add HTTP Basic later
    delete req.headers["x-authorization"];

    // Delete any attempts at cookies
    delete req.headers["cookie"];

    // Validate token if enabled
    if (process.env.USE_AUTH_TOKEN &&
        process.env.USE_AUTH_TOKEN == "true" &&
        process.env.AUTH_TOKEN_KEY &&
        process.env.AUTH_TOKEN_KEY.length > 0) {

        // Ensure we have a value
        if (!authHeaderValue) {
            denyAccess("missing header", res, req);
            return;
        }

        // Parse out the token
        var token = authHeaderValue.replace("Bearer ", "");

        var decoded = null;
        try {
            // Decode token
            decoded = jwt.verify(token, process.env.AUTH_TOKEN_KEY);
        } catch (err) {
            logSplunkError("jwt verify failed, x-authorization: " + authHeaderValue + "; err: " + err);
            denyAccess("jwt unverifiable", res, req);
            return;
        }

        console.log('CAPTCHA2 Past try/catch block');

        // Ensure we have a nonce
        if (decoded == null ||
            decoded.data.nonce == null ||
            decoded.data.nonce.length < 1) {
            denyAccess("missing nonce", res, req);
            return;
        }

        console.log('CAPTCHA3 Past decode block. Decoded Data: \n\n', JSON.stringify(decoded.data), '\n');

        // Check against the resource URL
        // typical URL:
        //    /MSPDESubmitApplication/2ea5e24c-705e-f7fd-d9f0-eb2dd268d523?programArea=enrolment
        var pathname = url.parse(req.url).pathname;
        var pathnameParts = pathname.split("/");

        // ? Idea for nouns: What about implmeneting uuid's in URLS for FPC? Maybe easier to track logs? 
        // TODO: Need to remove these checks for FPC. But don't forget they use decoded.data.nonce to check the noun.
        // Looks like they're just checking the URL contains the nonce. Why would we care about that for FPC?
        // TODO: Use configurable env variables to bypass
        console.log('CAPTCHA4 Bypassing MSPDE noun check.')
        // find the noun(s)
        // var nounIndex = pathnameParts.indexOf("MSPDESubmitAttachment");
        // if (nounIndex < 0) {
        //     nounIndex = pathnameParts.indexOf("MSPDESubmitApplication");
        // }

        // if (nounIndex < 0 ||
        //     pathnameParts.length < nounIndex + 2) {
        //     denyAccess("missing noun or resource id", res, req);
        //     return;
        // }

        // // Finally, check that resource ID against the nonce
        // if (pathnameParts[nounIndex + 1] != decoded.data.nonce) {
        //     denyAccess("resource id and nonce are not equal: " + pathnameParts[nounIndex + 1] + "; " + decoded.data.nonce, res, req);
        //     return;
        // }
    }
    // OK its valid let it pass thru this event
    next(); // pass control to the next handler
});


// Create new HTTPS.Agent for mutual TLS purposes
if (process.env.USE_MUTUAL_TLS &&
    process.env.USE_MUTUAL_TLS == "true") {
    var httpsAgentOptions = {
        key: new Buffer(process.env.MUTUAL_TLS_PEM_KEY_BASE64, 'base64'),
        passphrase: process.env.MUTUAL_TLS_PEM_KEY_PASSPHRASE,
        cert: new Buffer(process.env.MUTUAL_TLS_PEM_CERT, 'base64')
    };

    var myAgent = new https.Agent(httpsAgentOptions);
}
//
// Create a HTTP Proxy server with a HTTPS target
//
var proxy = proxy({
    target: process.env.TARGET_URL || "http://localhost:3000",
    agent: myAgent || http.globalAgent,
    secure: process.env.SECURE_MODE || false,
    keepAlive: true,
    changeOrigin: true,
    auth: process.env.TARGET_USERNAME_PASSWORD || "username:password",
    logLevel: 'info',
    logProvider: logProvider,

    //
    // Listen for the `error` event on `proxy`.
    //
    onError: function (err, req, res) {
        logSplunkError("proxy error: " + err + "; req.url: " + req.url + "; status: " + res.statusCode);
        res.writeHead(500, {
            'Content-Type': 'text/plain'
        });

        res.end('Error with proxy');
    },


    //
    // Listen for the `proxyRes` event on `proxy`.
    //
    onProxyRes: function (proxyRes, req, res) {
        // winston.info('RAW Response from the target: ' + stringify(proxyRes.headers));
        // TODO: REMOVE THIS LINE! WE SHOULD NOT BE LOGGING THE WHOLE REQUEST AFTER DEV, COULD BE PII
        // winston.info('FULL Response from Target (TODO REMOVE!): ' + stringify({headers: proxyRes.headers, body: proxyRes.body}));
        // Delete set-cookie
        delete proxyRes.headers["set-cookie"];
    },

    //
    // Listen for the `proxyReq` event on `proxy`.
    //
    onProxyReq: function(proxyReq, req, res, options) {
        //winston.info('RAW proxyReq: ', stringify(proxyReq.headers));
    //    logSplunkInfo('RAW URL: ' + req.url + '; RAW headers: ', stringify(req.headers));
        //winston.info('RAW options: ', stringify(options));
    }
});

// Add in proxy AFTER authorization
app.use('/', proxy);

// Start express
app.listen(8080);


/**
 * General deny access handler
 * @param message
 * @param res
 * @param req
 */
function denyAccess(message, res, req) {

    logSplunkError(message + " - access denied.  request: " + stringify(req.headers));

    res.writeHead(401);
    res.end();
    console.log('denyAccess: ' + message); //TODO: REMOVE
}

function logSplunkError (message) {

    //No point in calling this function if we don't have Splunk's address
    if (!process.env.LOGGER_HOST || !process.env.LOGGER_PORT){
        // console.log('logSplunkError called without Splunk setup:', message);
        return;
    }

    // log locally
    winston.error(message);

    var body = JSON.stringify({
        message: message
    })


    var options = {
        hostname: process.env.LOGGER_HOST,
        port: process.env.LOGGER_PORT,
        path: '/log',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Splunk ' + process.env.SPLUNK_AUTH_TOKEN,
            'Content-Length': Buffer.byteLength(body),
            'logsource': process.env.HOSTNAME,
            'timestamp': moment().format('DD-MMM-YYYY'),
            'program': 'msp-service',
            'serverity': 'error'
        }
    };

    var req = http.request(options, function (res) {
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            console.log("Body chunk: " + JSON.stringify(chunk));
        });
        res.on('end', function () {
            console.log('End of chunks');
        });
    });

    req.on('error', function (e) {
        console.error("error sending to splunk-forwarder: " + e.message);
    });

    // write data to request body
    req.write(body);
    req.end();
}

function logSplunkInfo (message) {

    //No point in calling this function if we don't have Splunk's address
    if (!process.env.LOGGER_HOST || !process.env.LOGGER_PORT){
        // console.log('logSplunkInfo called without Splunk setup:', message);
        return;
    }

    // log locally
    winston.info(message);

    var body = JSON.stringify({
        message: message
    })

    var options = {
        hostname: process.env.LOGGER_HOST,
        port: process.env.LOGGER_PORT,
        path: '/log',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Splunk ' + process.env.SPLUNK_AUTH_TOKEN,
            'Content-Length': Buffer.byteLength(body),
            'logsource': process.env.HOSTNAME,
            'timestamp': moment().format('DD-MMM-YYYY'),
            'method': 'MSP-Service - Pass Through',
            'program': 'msp-service',
            'serverity': 'info'
        }
    };

    var req = http.request(options, function (res) {
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
            console.log("Body chunk: " + JSON.stringify(chunk));
        });
        res.on('end', function () {
            console.log('End of chunks');
        });
    });

    req.on('error', function (e) {
        console.error("error sending to splunk-forwarder: " + e.message);
    });

    // write data to request body
    req.write(body);
    req.end();
}

logSplunkInfo('MyGovBC-MSP-Service server started on port 8080');



