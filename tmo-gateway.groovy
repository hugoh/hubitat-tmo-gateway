/**
 * Virtual button to reboot T-Mobile Internet Router
 *
 * Heavily inspired by https://github.com/highvolt-dev/tmo-monitor
 * MIT License
 * Copyright (c) 2021 highvolt-dev
 * Copyright (c) 2023 Hugo Haas
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Supported hardware:
 * - Nokia gateway
 */

metadata {
    definition(
//            name: "T-Mobile Internet Router Reboot Button",
            name: "tmo-router-reboot-switch",
            namespace: "hugoh",
            author: "Hugo Haas") {
        capability "Actuator"

        command "reboot", []

        attribute "nonce","string"
        attribute "csrfToken","string"
        attribute "webJar","string"
    }

    preferences {
        input name: "username", type: "string", title: "T-Mobile Router Username"
        input name: "password", type: "string", title: "T-Mobile Router Password"
        input name: "IP", type: "string", title: "Router IP address", defaultValue: "192.168.12.1"
        input name: "logEnable", type: "bool", title: "Enable debug logging", defaultValue: false
    }
}

void logDebug(msg) {
    if (logEnable) {
        log.debug msg
    }
}

// Functions using authenticated web API endpoints
def reboot() {
    String nonce
    String sid
    String token
    // Login
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
            logDebug("Login request: ${loginRequestJson}")
            httpPost(loginRequest, { loginResp ->
                if (loginResp?.isSuccess()) {
                    def resp = loginResp.getData().toString()
                    logDebug("Login response: ${resp}")
                    def loginJson = parseJson(resp)
                    sid = loginJson.sid
                    logDebug("Sid: {sid}")
                    token = loginJson.token
                    logDebug("Token: ${token}")
                }
            })
        }
    })
    if (!nonce || !token || !sid) {
        log.error("Error logging in")
        return;
    }
    // Reboot
    def rebootRequest = [
            'uri' : "http://${settings.IP}/reboot_web_app.cgi",
            headers: [
                "Cookie": "sid=${sid}"
            ],
            'body': [
                    'csrf_token'     : token,
            ]
    ]
    logDebug("Reboot request: ${loginRequestJson}")
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