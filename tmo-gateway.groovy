/**
 * Virtual button to reboot T-Mobile Internet Router
 *
 * Credits for the logic go to highvolt-dev: https://github.com/highvolt-dev/tmo-monitor
 */

metadata {
    definition(
            name: "T-Mobile Internet Router Reboot Button",
            namespace: "hugoh",
            author: "Hugo Haas",
            importUrl: "https://raw.githubusercontent.com/hugoh/hubitat-tmo-gateway/master/tmo-gateway.groovy") {
        capability "Actuator"

        command "reboot", []
    }

    preferences {
        input name: "username", type: "string", title: "T-Mobile Router Username"
        input name: "password", type: "string", title: "T-Mobile Router Password"
        input name: "IP", type: "string", title: "Router IP address", defaultValue: "192.168.12.1"
        input name: "Gateway", type: "enum", title: "Type of gateway", options: ["Nokia"], defaultValue: "Nokia"
        input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: false
    }
}

void logDebug(msg) {
    if (logEnable) {
        log.debug msg
    }
}

boolean login() {
    boolean success = false
    httpGet("http://${settings.IP}/login_web_app.cgi?nonce", { nonceResp ->
        if (nonceResp?.isSuccess()) {
            def nonceJson = parseJson(nonceResp.getData().toString())
            logDebug("Got nonce JSON: ${nonceJson}")
            nonce = nonceJson.nonce
            logDebug("Got nonce: ${nonce}")
            def passHashInput = settings.password.toLowerCase()
            def userPassHash = sha256(settings.username, passHashInput)
            def userPassNonceHash = sha256url(userPassHash, nonce)
            def loginRequest = [
                    'uri' : "http://${settings.IP}/login_web_app.cgi",
                    'body': [
                            'userhash'     : sha256url(settings.username, nonce),
                            'RandomKeyhash': sha256url(nonceJson.randomKey, nonce),
                            'response'     : userPassNonceHash,
                            'nonce'        : base64urlEscape(nonce),
                            'enckey'       : random16bytes(),
                            'enciv'        : random16bytes()
                    ]
            ]
            logDebug("Login request: ${loginRequest}")
            httpPost(loginRequest, { loginResp ->
                if (loginResp?.isSuccess()) {
                    def resp = loginResp.getData().toString()
                    logDebug("Login response: ${resp}")
                    def loginJson = parseJson(resp)
                    state.sid = loginJson.sid
                    logDebug("Sid: ${state.sid}")
                    state.csrfToken = loginJson.token
                    logDebug("Token: ${state.csrfToken}")
                    success = true
                }
            })
        }
    })
    state.loginSuccessful = success
}

def reboot() {
    login()
    if (!state.loginSuccessful) {
        log.error("Cannot reboot without successful login flow")
        return
    }
    def rebootRequest = [
            'uri' : "http://${settings.IP}/reboot_web_app.cgi",
            headers: [
                "Cookie": "sid=${state.sid}"
            ],
            'body': [
                    'csrf_token'     : state.csrfToken,
            ]
    ]
    logDebug("Reboot request: ${rebootRequest}")
    httpPost(rebootRequest, { rebootResp ->
        resp = rebootResp.getData()
        if (rebootResp?.isSuccess()) {
            logDebug("Reboot response: ${resp}")
            log.info("T-Mobile Internet Router reboot successfully requested")
        } else {
            log.error("Reboot request failed: ${resp}")
        }
    })
}

String base64urlEscape(String b64) {
    String out = ''
    for (char c : b64.toCharArray()) {
        switch (c) {
            case '+':
                out += '-'
                break
            case '/':
                out += '_'
                break
            case '=':
                out += '.'
                break
            default:
                out += c
                break
        }
    }
    return out
}

String sha256(String val1, String val2) {
    def hash = java.security.MessageDigest.getInstance("SHA-256")
    hash.update("${val1}:${val2}".getBytes('UTF-8'))
    return hash.digest().encodeBase64().toString()
}

String sha256url(String val1, String val2) {
    return base64urlEscape(sha256(val1, val2))
}

String random16bytes() {
    Random r = new Random();
    byte[] bytes = new byte[16]
    r.nextBytes(bytes)
    return base64urlEscape(bytes.encodeBase64().toString())
}
