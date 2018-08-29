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
if (process.env.BYPASS_CAPTCHA_URLS && process.env.BYPASS_CAPTCHA_URLS.length){

    const bypassCaptchaURLs = process.env.BYPASS_CAPTCHA_URLS
        .replace(/ /g, '') // Remove all spaces, if any exist they're just a user entry error
        .split(',') // convert csv into array
        .map(url => url.replace(/^\/+/g, '')) // Remove leading slashes on each url if any
        .map(url => url.replace(/\/+$/, "")) // Remove trailing slashes on each url if any

    winston.info('Formatted bypass captcha URLS:', JSON.stringify(bypassCaptchaURLs));
}

//
// CAPTCHA Authorization, ALWAYS first
//
app.use('/', function (req, res, next) {
    // Delete headers from Oracle and other backend services
    // TODO: Verify this works. Maybe we have to do delete from res.headers?
    delete req.headers['x-oracle-dms-ecid'];
    // delete req.headers['x-oracle-dms-rid'];
    delete req.headers['x-weblogic-force-jvmid'];
    delete req.headers['breadcrumbid'];
    delete req.headers['x-weblogic-request-clusterinfo'];

    delete res.headers['x-oracle-dms-rid']; //! test if this works instead of req.headres

    // Log it
    // logSplunkInfo("incoming: ", req.method, req.headers.host, req.url, res.statusCode, req.headers["x-authorization"]);

    // Get authorization from browser
    var authHeaderValue = req.headers["x-authorization"];

    // Delete it because we add HTTP Basic later
    delete req.headers["x-authorization"];

    // Delete any attempts at cookies
    delete req.headers["cookie"];

    // format the request url so we can easily compare it, removing leading slashes
    const formattedRequestURL = req.originalUrl.replace(/^\/+/g, '');

    // Bypass CAPTCHA check and exit out of this function
    if( bypassCaptchaURLs && bypassCaptchaURLs.includes(formattedRequestURL) ){
        return next();
    }

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

        // Ensure we have a nonce
        if (decoded == null ||
            decoded.data.nonce == null ||
            decoded.data.nonce.length < 1) {
            denyAccess("missing nonce", res, req);
            return;
        }

        // TODO: Use env variables to bypass hardcoded MSP logic instead of just commenting out
        // ! Discuss with Jam how to add env variables. Didn't we have to modify OpenShift templates (json)?
        // Simple fix: Just add a true/false env variable to bypass this. Have default (undefined) to behaviour MSP wants.
        // Better fix: Add "nouns" as env variable; if any are defined then the nonce must follow at least one noun in URL

        // // Check against the resource URL
        // // typical URL:
        // //    /MSPDESubmitApplication/2ea5e24c-705e-f7fd-d9f0-eb2dd268d523?programArea=enrolment
        // // var pathname = url.parse(req.url).pathname;
        // // var pathnameParts = pathname.split("/");
        // // find the noun(s)
        // // var nounIndex = pathnameParts.indexOf("MSPDESubmitAttachment");
        // // if (nounIndex < 0) {
        // //     nounIndex = pathnameParts.indexOf("MSPDESubmitApplication");
        // // }

        // // if (nounIndex < 0 ||
        // //     pathnameParts.length < nounIndex + 2) {
        // //     denyAccess("missing noun or resource id", res, req);
        // //     return;
        // // }

        // // // Finally, check that resource ID against the nonce
        // // if (pathnameParts[nounIndex + 1] != decoded.data.nonce) {
        // //     denyAccess("resource id and nonce are not equal: " + pathnameParts[nounIndex + 1] + "; " + decoded.data.nonce, res, req);
        // //     return;
        // // }
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
}

function logSplunkError (message) {
    // log locally
    winston.error(message);

    //No point in continuing in this function if we don't have Splunk's address
    if (!process.env.LOGGER_HOST || !process.env.LOGGER_PORT){
        // console.log('logSplunkError called without Splunk setup:', message);
        return;
    }

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
    // log locally
    winston.info(message);

    //No point in continuing this function if we don't have Splunk's address
    if (!process.env.LOGGER_HOST || !process.env.LOGGER_PORT){
        // console.log('logSplunkInfo called without Splunk setup:', message);
        return;
    }

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



